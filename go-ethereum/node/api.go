// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package node

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/metrics"
	"github.com/ethereum/go-ethereum/p2p"
	"github.com/ethereum/go-ethereum/p2p/discover"
	"github.com/ethereum/go-ethereum/rpc"
)

// PrivateAdminAPI is the collection of administrative API methods exposed only
// over a secure RPC channel.
type PrivateAdminAPI struct {
	node *Node // Node interfaced by this API
}

// NewPrivateAdminAPI creates a new API definition for the private admin methods
// of the node itself.
func NewPrivateAdminAPI(node *Node) *PrivateAdminAPI {
	return &PrivateAdminAPI{node: node}
}

//////////////////////////
//  connect libsnark
//////////////////////////
func checkGenConnection(conn net.Conn, err error) bool {
	if err != nil {
		log.Warn(err.Error())
		fmt.Printf("error %v connecting, please check hdsnark\n", conn)
		return false
	}
	fmt.Printf("connected with %v\n", conn)
	return true
}

func localGenConnection(inputData []byte) ([]byte, uint32) {
	conn, err := net.Dial("tcp", "127.0.0.1:8032")
	if !checkGenConnection(conn, err) {
		return nil, 0
	}

	conn.Write(inputData) // send original data

	receiveData := make([]byte, 2048)

	indexEnd, err := conn.Read(receiveData)

	if err != nil {
		log.Warn(err.Error())
		return nil, 0
	}

	// var result uint32
	// resIndex := (int)(unsafe.Sizeof(result))
	// result = uint32(binary.LittleEndian.Uint32(receiveData[0:resIndex]))

	result := (uint32)(receiveData[0] - 48)
	for i := 1; i < 4; i++ {
		result = 10*result + (uint32)(receiveData[i]-48)
	}

	proofLen := 1152
	proof := make([]byte, proofLen)
	proof = receiveData[4:indexEnd]

	// fmt.Printf("receive proof: ")
	// fmt.Println(proof)
	// fmt.Printf("receive result: ")
	// fmt.Println(result)

	defer conn.Close()
	return proof, result
}

// GenProof returns a proof and result.
func (api *PrivateAdminAPI) GenProof(secretData []byte, hashData []byte, pubParas []byte) (bool, error) {
	// Make sure the server is running, fail otherwise
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}

	// hashData := sha256.Sum256(secretData)
	// hashCoeff := sha256.Sum256(pubParas)

	// Try to add the url as a static peer and return
	fmt.Println("sending these data to libsnark to gennerate proof!!!")
	// fmt.Printf("hashData: ")
	// fmt.Println(hashData)
	// fmt.Printf("secretData: ")
	// fmt.Println(secretData)
	// fmt.Printf("hashCoeff: ")
	// fmt.Println(hashCoeff)
	// fmt.Printf("pubParas: ")
	// fmt.Println(pubParas)

	var buffer bytes.Buffer   // Buffer can be write and read with byte
	messageID := []byte{0, 0} // 00 represents original data

	buffer.Write(messageID)
	buffer.Write(hashData[:])
	buffer.Write(secretData)
	// buffer.Write(hashCoeff[:])
	// insert pubParas len
	newPubParas := make([]byte, 0, len(pubParas)+1)
	newPubParas = append(newPubParas, byte(len(pubParas)))
	for i := 0; i < len(pubParas); i++ {
		newPubParas = append(newPubParas, pubParas[i])
	}
	fmt.Println(newPubParas)
	//copy(newPubParas[1:], pubParas)
	buffer.Write(newPubParas)
	// buffer.Write(pubParas)
	inputData := buffer.Bytes()

	fmt.Printf("inputData: ")
	fmt.Println(inputData)

	// //============================================
	// // former return for test.
	// fmt.Printf("coeff len is %d\n", len(pubParas))
	// fmt.Printf("secretData len is %d\n", len(secretData))
	
	// resultByte := 0
	// for i := 0; i < len(pubParas); i++{
	// 	resultByte += int(secretData[i]) * int(pubParas[i])
	// 	// fmt.Println(resultByte)
	// }
	// fmt.Printf("Result = %d\n", resultByte)

	// fmt.Printf("h_data_bv = ")
	// PrintByteArray(hashData[:])
	// fmt.Printf("tuple_data_bv = ")
	// PrintByteArray(secretData)
	// fmt.Printf("data_coeff_bv = ")
	// PrintByteArray(pubParas)
	// fmt.Printf("premium_bv = int_list_to_bits({%d, %d}, 8);\n", resultByte/256, resultByte%256)

	// return true, nil
	// ////////////////////////////////

	proof := make([]byte, 0, 1152)
	proof, result := localGenConnection(inputData)

	if len(proof) == 0 {
		return false, nil
	}

	fmt.Println("receive data: \n\n")
	fmt.Printf("proof = \"0x%s\"\n", hex.EncodeToString(proof))
	//fmt.Printf("proof = ")
	//PrintByteArray(proof)
	// fmt.Println(proof)

	fmt.Printf("premium = %d\n", result)
	// resArray := make([]byte, 0, 2)
	// resArray = append(resArray, (byte)(result/256), (byte)(result%256))
	// fmt.Printf("premium = ")
	// PrintByteArray(resArray)
	// fmt.Println(result)

	fmt.Printf("hashData = \"0x%s\"\n", hex.EncodeToString(hashData))
	// fmt.Println(hashData)
	// PrintByteArray(hashData[:])

	fmt.Printf("coeff = \"0x%s\"\n\n", hex.EncodeToString(newPubParas))
	// fmt.Printf("hashCoeff = ")
	// fmt.Println(hashCoeff)
	// PrintByteArray(hashCoeff[:])

	return true, nil
}

func PrintByteArray(data []byte) {
	fmt.Printf("int_list_to_bits({%d", data[0])
	lenData := len(data)
	for i := 1; i < lenData-1; i++ {
		fmt.Printf(", %d", data[i])
	}
	fmt.Printf(", %d}, 8);\n", data[lenData-1])
}

// AddPeer requests connecting to a remote node, and also maintaining the new
// connection at all times, even reconnecting if it is lost.
func (api *PrivateAdminAPI) AddPeer(url string) (bool, error) {
	// Make sure the server is running, fail otherwise
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	// Try to add the url as a static peer and return
	node, err := discover.ParseNode(url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	server.AddPeer(node)
	return true, nil
}

// RemovePeer disconnects from a a remote node if the connection exists
func (api *PrivateAdminAPI) RemovePeer(url string) (bool, error) {
	// Make sure the server is running, fail otherwise
	server := api.node.Server()
	if server == nil {
		return false, ErrNodeStopped
	}
	// Try to remove the url as a static peer and return
	node, err := discover.ParseNode(url)
	if err != nil {
		return false, fmt.Errorf("invalid enode: %v", err)
	}
	server.RemovePeer(node)
	return true, nil
}

// PeerEvents creates an RPC subscription which receives peer events from the
// node's p2p.Server
func (api *PrivateAdminAPI) PeerEvents(ctx context.Context) (*rpc.Subscription, error) {
	// Make sure the server is running, fail otherwise
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}

	// Create the subscription
	notifier, supported := rpc.NotifierFromContext(ctx)
	if !supported {
		return nil, rpc.ErrNotificationsUnsupported
	}
	rpcSub := notifier.CreateSubscription()

	go func() {
		events := make(chan *p2p.PeerEvent)
		sub := server.SubscribeEvents(events)
		defer sub.Unsubscribe()

		for {
			select {
			case event := <-events:
				notifier.Notify(rpcSub.ID, event)
			case <-sub.Err():
				return
			case <-rpcSub.Err():
				return
			case <-notifier.Closed():
				return
			}
		}
	}()

	return rpcSub, nil
}

// StartRPC starts the HTTP RPC API server.
func (api *PrivateAdminAPI) StartRPC(host *string, port *int, cors *string, apis *string, vhosts *string) (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	if api.node.httpHandler != nil {
		return false, fmt.Errorf("HTTP RPC already running on %s", api.node.httpEndpoint)
	}

	if host == nil {
		h := DefaultHTTPHost
		if api.node.config.HTTPHost != "" {
			h = api.node.config.HTTPHost
		}
		host = &h
	}
	if port == nil {
		port = &api.node.config.HTTPPort
	}

	allowedOrigins := api.node.config.HTTPCors
	if cors != nil {
		allowedOrigins = nil
		for _, origin := range strings.Split(*cors, ",") {
			allowedOrigins = append(allowedOrigins, strings.TrimSpace(origin))
		}
	}

	allowedVHosts := api.node.config.HTTPVirtualHosts
	if vhosts != nil {
		allowedVHosts = nil
		for _, vhost := range strings.Split(*host, ",") {
			allowedVHosts = append(allowedVHosts, strings.TrimSpace(vhost))
		}
	}

	modules := api.node.httpWhitelist
	if apis != nil {
		modules = nil
		for _, m := range strings.Split(*apis, ",") {
			modules = append(modules, strings.TrimSpace(m))
		}
	}

	if err := api.node.startHTTP(fmt.Sprintf("%s:%d", *host, *port), api.node.rpcAPIs, modules, allowedOrigins, allowedVHosts); err != nil {
		return false, err
	}
	return true, nil
}

// StopRPC terminates an already running HTTP RPC API endpoint.
func (api *PrivateAdminAPI) StopRPC() (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	if api.node.httpHandler == nil {
		return false, fmt.Errorf("HTTP RPC not running")
	}
	api.node.stopHTTP()
	return true, nil
}

// StartWS starts the websocket RPC API server.
func (api *PrivateAdminAPI) StartWS(host *string, port *int, allowedOrigins *string, apis *string) (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	if api.node.wsHandler != nil {
		return false, fmt.Errorf("WebSocket RPC already running on %s", api.node.wsEndpoint)
	}

	if host == nil {
		h := DefaultWSHost
		if api.node.config.WSHost != "" {
			h = api.node.config.WSHost
		}
		host = &h
	}
	if port == nil {
		port = &api.node.config.WSPort
	}

	origins := api.node.config.WSOrigins
	if allowedOrigins != nil {
		origins = nil
		for _, origin := range strings.Split(*allowedOrigins, ",") {
			origins = append(origins, strings.TrimSpace(origin))
		}
	}

	modules := api.node.config.WSModules
	if apis != nil {
		modules = nil
		for _, m := range strings.Split(*apis, ",") {
			modules = append(modules, strings.TrimSpace(m))
		}
	}

	if err := api.node.startWS(fmt.Sprintf("%s:%d", *host, *port), api.node.rpcAPIs, modules, origins, api.node.config.WSExposeAll); err != nil {
		return false, err
	}
	return true, nil
}

// StopWS terminates an already running websocket RPC API endpoint.
func (api *PrivateAdminAPI) StopWS() (bool, error) {
	api.node.lock.Lock()
	defer api.node.lock.Unlock()

	if api.node.wsHandler == nil {
		return false, fmt.Errorf("WebSocket RPC not running")
	}
	api.node.stopWS()
	return true, nil
}

// PublicAdminAPI is the collection of administrative API methods exposed over
// both secure and unsecure RPC channels.
type PublicAdminAPI struct {
	node *Node // Node interfaced by this API
}

// NewPublicAdminAPI creates a new API definition for the public admin methods
// of the node itself.
func NewPublicAdminAPI(node *Node) *PublicAdminAPI {
	return &PublicAdminAPI{node: node}
}

// Peers retrieves all the information we know about each individual peer at the
// protocol granularity.
func (api *PublicAdminAPI) Peers() ([]*p2p.PeerInfo, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	return server.PeersInfo(), nil
}

// NodeInfo retrieves all the information we know about the host node at the
// protocol granularity.
func (api *PublicAdminAPI) NodeInfo() (*p2p.NodeInfo, error) {
	server := api.node.Server()
	if server == nil {
		return nil, ErrNodeStopped
	}
	return server.NodeInfo(), nil
}

// Datadir retrieves the current data directory the node is using.
func (api *PublicAdminAPI) Datadir() string {
	return api.node.DataDir()
}

// PublicDebugAPI is the collection of debugging related API methods exposed over
// both secure and unsecure RPC channels.
type PublicDebugAPI struct {
	node *Node // Node interfaced by this API
}

// NewPublicDebugAPI creates a new API definition for the public debug methods
// of the node itself.
func NewPublicDebugAPI(node *Node) *PublicDebugAPI {
	return &PublicDebugAPI{node: node}
}

// Metrics retrieves all the known system metric collected by the node.
func (api *PublicDebugAPI) Metrics(raw bool) (map[string]interface{}, error) {
	// Create a rate formatter
	units := []string{"", "K", "M", "G", "T", "E", "P"}
	round := func(value float64, prec int) string {
		unit := 0
		for value >= 1000 {
			unit, value, prec = unit+1, value/1000, 2
		}
		return fmt.Sprintf(fmt.Sprintf("%%.%df%s", prec, units[unit]), value)
	}
	format := func(total float64, rate float64) string {
		return fmt.Sprintf("%s (%s/s)", round(total, 0), round(rate, 2))
	}
	// Iterate over all the metrics, and just dump for now
	counters := make(map[string]interface{})
	metrics.DefaultRegistry.Each(func(name string, metric interface{}) {
		// Create or retrieve the counter hierarchy for this metric
		root, parts := counters, strings.Split(name, "/")
		for _, part := range parts[:len(parts)-1] {
			if _, ok := root[part]; !ok {
				root[part] = make(map[string]interface{})
			}
			root = root[part].(map[string]interface{})
		}
		name = parts[len(parts)-1]

		// Fill the counter with the metric details, formatting if requested
		if raw {
			switch metric := metric.(type) {
			case metrics.Counter:
				root[name] = map[string]interface{}{
					"Overall": float64(metric.Count()),
				}

			case metrics.Meter:
				root[name] = map[string]interface{}{
					"AvgRate01Min": metric.Rate1(),
					"AvgRate05Min": metric.Rate5(),
					"AvgRate15Min": metric.Rate15(),
					"MeanRate":     metric.RateMean(),
					"Overall":      float64(metric.Count()),
				}

			case metrics.Timer:
				root[name] = map[string]interface{}{
					"AvgRate01Min": metric.Rate1(),
					"AvgRate05Min": metric.Rate5(),
					"AvgRate15Min": metric.Rate15(),
					"MeanRate":     metric.RateMean(),
					"Overall":      float64(metric.Count()),
					"Percentiles": map[string]interface{}{
						"5":  metric.Percentile(0.05),
						"20": metric.Percentile(0.2),
						"50": metric.Percentile(0.5),
						"80": metric.Percentile(0.8),
						"95": metric.Percentile(0.95),
					},
				}

			case metrics.ResettingTimer:
				t := metric.Snapshot()
				ps := t.Percentiles([]float64{5, 20, 50, 80, 95})
				root[name] = map[string]interface{}{
					"Measurements": len(t.Values()),
					"Mean":         t.Mean(),
					"Percentiles": map[string]interface{}{
						"5":  ps[0],
						"20": ps[1],
						"50": ps[2],
						"80": ps[3],
						"95": ps[4],
					},
				}

			default:
				root[name] = "Unknown metric type"
			}
		} else {
			switch metric := metric.(type) {
			case metrics.Counter:
				root[name] = map[string]interface{}{
					"Overall": float64(metric.Count()),
				}

			case metrics.Meter:
				root[name] = map[string]interface{}{
					"Avg01Min": format(metric.Rate1()*60, metric.Rate1()),
					"Avg05Min": format(metric.Rate5()*300, metric.Rate5()),
					"Avg15Min": format(metric.Rate15()*900, metric.Rate15()),
					"Overall":  format(float64(metric.Count()), metric.RateMean()),
				}

			case metrics.Timer:
				root[name] = map[string]interface{}{
					"Avg01Min": format(metric.Rate1()*60, metric.Rate1()),
					"Avg05Min": format(metric.Rate5()*300, metric.Rate5()),
					"Avg15Min": format(metric.Rate15()*900, metric.Rate15()),
					"Overall":  format(float64(metric.Count()), metric.RateMean()),
					"Maximum":  time.Duration(metric.Max()).String(),
					"Minimum":  time.Duration(metric.Min()).String(),
					"Percentiles": map[string]interface{}{
						"5":  time.Duration(metric.Percentile(0.05)).String(),
						"20": time.Duration(metric.Percentile(0.2)).String(),
						"50": time.Duration(metric.Percentile(0.5)).String(),
						"80": time.Duration(metric.Percentile(0.8)).String(),
						"95": time.Duration(metric.Percentile(0.95)).String(),
					},
				}

			case metrics.ResettingTimer:
				t := metric.Snapshot()
				ps := t.Percentiles([]float64{5, 20, 50, 80, 95})
				root[name] = map[string]interface{}{
					"Measurements": len(t.Values()),
					"Mean":         time.Duration(t.Mean()).String(),
					"Percentiles": map[string]interface{}{
						"5":  time.Duration(ps[0]).String(),
						"20": time.Duration(ps[1]).String(),
						"50": time.Duration(ps[2]).String(),
						"80": time.Duration(ps[3]).String(),
						"95": time.Duration(ps[4]).String(),
					},
				}

			default:
				root[name] = "Unknown metric type"
			}
		}
	})
	return counters, nil
}

// PublicWeb3API offers helper utils
type PublicWeb3API struct {
	stack *Node
}

// NewPublicWeb3API creates a new Web3Service instance
func NewPublicWeb3API(stack *Node) *PublicWeb3API {
	return &PublicWeb3API{stack}
}

// ClientVersion returns the node name
func (s *PublicWeb3API) ClientVersion() string {
	return s.stack.Server().Name
}

// Sha3 applies the ethereum sha3 implementation on the input.
// It assumes the input is hex encoded.
func (s *PublicWeb3API) Sha3(input hexutil.Bytes) hexutil.Bytes {
	return crypto.Keccak256(input)
}
