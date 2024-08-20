package network // import "collectd.org/network"

import (
	"context"
	"log"
	"net"
	"sync"

	"collectd.org/api"
)

// ListenAndWrite listens on the provided UDP address, parses the received
// packets and writes them to the provided api.Writer.
// This is a convenience function for a minimally configured server. If you
// need more control, see the "Server" type below.
func ListenAndWrite(ctx context.Context, address string, d api.Writer) error {
	srv := &Server{
		Addr:   address,
		Writer: d,
	}

	return srv.ListenAndWrite(ctx)
}

// Server holds parameters for running a collectd server.
type Server struct {
	// UDP connection the server listens on. If Conn is nil, a new server
	// connection is opened. The connection is closed by ListenAndWrite
	// before returning.
	Conn *net.UDPConn
	// Address to listen on if Conn is nil. If Addr is empty, too, then the
	// "any" interface and the DefaultService will be used.
	Addr           string
	Writer         api.Writer     // Object used to send incoming ValueLists to.
	BufferSize     uint16         // Maximum packet size to accept.
	PasswordLookup PasswordLookup // User to password lookup.
	SecurityLevel  SecurityLevel  // Minimal required security level.
	TypesDB        *api.TypesDB   // TypesDB for looking up DS names and verify data source types.
	// Interface is the name of the interface to use when subscribing to a
	// multicast group. Has no effect when using unicast.
	Interface string

	// Channel buffer on dispatcher, this limits how many packets/value lists
	// can be held in flight before we block on reading new value lists from the network.
	// Defaults to 1024
	DispatchBufferSize uint

	// Logger defines a log.Logger that can optionally be provided for handling log messages
	// if none is provided a log.Default() is assigned
	Logger *log.Logger
}

// ListenAndWrite listens on the provided UDP connection (or creates one using
// Addr if Conn is nil), parses the received packets and writes them to the
// provided api.Writer.
func (srv *Server) ListenAndWrite(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if srv.Conn == nil {
		addr := srv.Addr
		if addr == "" {
			addr = ":" + DefaultService
		}

		laddr, err := net.ResolveUDPAddr("udp", addr)
		if err != nil {
			return err
		}

		if laddr.IP != nil && laddr.IP.IsMulticast() {
			var ifi *net.Interface
			if srv.Interface != "" {
				if ifi, err = net.InterfaceByName(srv.Interface); err != nil {
					return err
				}
			}
			srv.Conn, err = net.ListenMulticastUDP("udp", ifi, laddr)
		} else {
			srv.Conn, err = net.ListenUDP("udp", laddr)
		}
		if err != nil {
			return err
		}
	}

	if srv.BufferSize <= 0 {
		srv.BufferSize = DefaultBufferSize
	}
	if srv.DispatchBufferSize <= 0 {
		srv.BufferSize = DefaultDispatcherBufferSize
	}

	if srv.Logger == nil {
		srv.Logger = log.Default()
	}

	popts := ParseOpts{
		PasswordLookup: srv.PasswordLookup,
		SecurityLevel:  srv.SecurityLevel,
		TypesDB:        srv.TypesDB,
	}

	go func() {
		select {
		case <-ctx.Done():
			// this interrupts the below Conn.Read().
			srv.Conn.Close()
		}
	}()

	var wg sync.WaitGroup

	valueListChan := make(chan []*api.ValueList, srv.DispatchBufferSize)
	wg.Add(1)
	go srv.dispatcher(ctx, &wg, valueListChan)

	for {
		buf := make([]byte, srv.BufferSize)
		n, err := srv.Conn.Read(buf)
		if err != nil {
			srv.Conn.Close()
			close(valueListChan)
			wg.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}

		valueLists, err := Parse(buf[:n], popts)
		if err != nil {
			srv.Logger.Printf("error while parsing: %v", err)
			continue
		}
		select {
		case <-ctx.Done():
			//if the context closed, just continue, we will clean up on the next loop iteration
			//when the srv.Conn.Read fails
		case valueListChan <- valueLists:
			//ALL good, we wrote to the channel
		}
	}
}

func (srv *Server) dispatcher(ctx context.Context, wg *sync.WaitGroup, valueListChan chan []*api.ValueList) {
	defer wg.Done()
	for vl := range valueListChan {
		for _, v := range vl {
			if err := srv.Writer.Write(ctx, v); err != nil {
				srv.Logger.Printf("error while dispatching: %v", err)
			}
		}
	}
}
