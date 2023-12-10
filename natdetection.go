package natdetection

import (
	"encoding/hex"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const Version = "0.1.0"

var (
	logger = log.New(os.Stdout, "nat.detection: ", log.LstdFlags)

	stunServers = []string{
		"stunserver.stunprotocol.org",
		"stun.hot-chilli.net",
		"stun.fitauto.ru",
		"stun.syncthing.net",
		"stun.qq.com",
		"stun.miwifi.com",
		"stun.voipbuster.com",
		"stun.voipstunt.com",
		"stun.voxgratia.org",
	}

	Defaults = map[string]interface{}{
		"stun_port":   3478,
		"source_ip":   "0.0.0.0",
		"source_port": 54320,
	}
)

const (
	// STUN attributes
	MappedAddress    = "0001"
	ResponseAddress  = "0002"
	ChangeRequest    = "0003"
	SourceAddress    = "0004"
	ChangedAddress   = "0005"
	Username         = "0006"
	Password         = "0007"
	MessageIntegrity = "0008"
	ErrorCode        = "0009"
	UnknownAttribute = "000A"
	ReflectedFrom    = "000B"
	XorOnly          = "0021"
	XorMappedAddress = "8020"
	ServerName       = "8022"
	SecondaryAddress = "8050"

	// STUN message types
	BindRequestMsg               = "0001"
	BindResponseMsg              = "0101"
	BindErrorResponseMsg         = "0111"
	SharedSecretRequestMsg       = "0002"
	SharedSecretResponseMsg      = "0102"
	SharedSecretErrorResponseMsg = "0112"
)

var (
	dictAttrToVal = map[string]string{
		"MappedAddress":    MappedAddress,
		"ResponseAddress":  ResponseAddress,
		"ChangeRequest":    ChangeRequest,
		"SourceAddress":    SourceAddress,
		"ChangedAddress":   ChangedAddress,
		"Username":         Username,
		"Password":         Password,
		"MessageIntegrity": MessageIntegrity,
		"ErrorCode":        ErrorCode,
		"UnknownAttribute": UnknownAttribute,
		"ReflectedFrom":    ReflectedFrom,
		"XorOnly":          XorOnly,
		"XorMappedAddress": XorMappedAddress,
		"ServerName":       ServerName,
		"SecondaryAddress": SecondaryAddress,
	}
	dictMsgTypeToVal = map[string]string{
		"BindRequestMsg":               BindRequestMsg,
		"BindResponseMsg":              BindResponseMsg,
		"BindErrorResponseMsg":         BindErrorResponseMsg,
		"SharedSecretRequestMsg":       SharedSecretRequestMsg,
		"SharedSecretResponseMsg":      SharedSecretResponseMsg,
		"SharedSecretErrorResponseMsg": SharedSecretErrorResponseMsg,
	}
	dictValToAttr    map[string]string
	dictValToMsgType map[string]string
)

type NatType string

const (
	Blocked              NatType = "Blocked"
	OpenInternet         NatType = "Open Internet"
	FullCone             NatType = "Full Cone"
	SymmetricUDPFirewall NatType = "Symmetric UDP Firewall"
	RestrictNAT          NatType = "Restrict Cone"
	RestrictPortNAT      NatType = "Port Restricted Cone"
	SymmetricNAT         NatType = "Symmetric"
	ChangedAddressError  NatType = "Meet an error, when do Test1 on Changed IP and Port"
)

func init() {
	dictValToAttr = make(map[string]string)
	dictValToMsgType = make(map[string]string)
	for key, value := range dictAttrToVal {
		dictValToAttr[value] = key
	}
	for key, value := range dictMsgTypeToVal {
		dictValToMsgType[value] = key
	}
}

func genTranID() string {
	const chars = "0123456789ABCDEF"
	result := make([]byte, 32)
	for i := range result {
		result[i] = chars[rand.Intn(len(chars))]
	}
	return string(result)
}

func StunTest(conn *net.UDPConn, host string, port int, sourceIP string, sourcePort int, sendData string) (map[string]interface{}, error) {
	retVal := map[string]interface{}{
		"Resp":         false,
		"ExternalIP":   nil,
		"ExternalPort": nil,
		"SourceIP":     nil,
		"SourcePort":   nil,
		"ChangedIP":    nil,
		"ChangedPort":  nil,
	}

	// Resolve domain name to IP address
	ips, err := net.LookupHost(host)
	if err != nil {
		return retVal, err
	}
	if len(ips) == 0 {
		return retVal, fmt.Errorf("no IP address found for host: %s", host)
	}

	// Use the first resolved IP address
	serverAddr := &net.UDPAddr{IP: net.ParseIP(ips[0]), Port: port}

	// Convert send data to bytes
	strLen := fmt.Sprintf("%04x", len(sendData)/2)
	tranID := genTranID()
	strData := BindRequestMsg + strLen + tranID + sendData
	data, err := hex.DecodeString(strData)
	if err != nil {
		return retVal, err
	}

	recvCorr := false
	for !recvCorr {
		received := false
		count := 3
		for !received {
			logger.Printf("sendto: %s, %d\n", host, port)
			_, err := conn.WriteToUDP(data, serverAddr)
			if err != nil {
				return retVal, err
			}

			conn.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, 2048)
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				logger.Printf("recvfrom error: %s\n", err)
				if count > 0 {
					count--
					continue
				}
				return retVal, err
			}

			bufHex := hex.EncodeToString(buf[:n])
			logger.Printf("recvfrom: %s, %s\n", addr, bufHex)
			received = true

			msgType := hex.EncodeToString(buf[0:2])
			bindRespMsg := dictValToMsgType[msgType] == "BindResponseMsg"
			tranIDMatch := strings.ToUpper(tranID) == strings.ToUpper(hex.EncodeToString(buf[4:20]))

			if bindRespMsg && tranIDMatch {
				recvCorr = true
				retVal["Resp"] = true
				lenMessage, _ := strconv.ParseInt(hex.EncodeToString(buf[2:4]), 16, 64)
				lenRemain := int(lenMessage)
				base := 20
				for lenRemain > 0 {
					attrType := hex.EncodeToString(buf[base : base+2])
					attrLen, _ := strconv.ParseInt(hex.EncodeToString(buf[base+2:base+4]), 16, 64)

					switch attrType {
					case MappedAddress:
						port := int(buf[base+6])<<8 + int(buf[base+7])
						ip := net.IPv4(buf[base+8], buf[base+9], buf[base+10], buf[base+11]).String()
						retVal["ExternalIP"] = ip
						retVal["ExternalPort"] = port

					case SourceAddress:
						port := int(buf[base+6])<<8 + int(buf[base+7])
						ip := net.IPv4(buf[base+8], buf[base+9], buf[base+10], buf[base+11]).String()
						retVal["SourceIP"] = ip
						retVal["SourcePort"] = port

					case ChangedAddress:
						port := int(buf[base+6])<<8 + int(buf[base+7])
						ip := net.IPv4(buf[base+8], buf[base+9], buf[base+10], buf[base+11]).String()
						retVal["ChangedIP"] = ip
						retVal["ChangedPort"] = port

						// Other
					}

					base += 4 + int(attrLen)
					lenRemain -= 4 + int(attrLen)
				}

			}
		}
	}
	return retVal, nil
}

// GetNATType determines the NAT type
func GetNATType(conn *net.UDPConn, sourceIP string, sourcePort int, stunHost string, stunPort int) (NatType, map[string]interface{}, error) {
	if stunHost == "" {
		for _, host := range stunServers {
			logger.Printf("trying STUN host: %s\n", host)
			ret, err := StunTest(conn, host, stunPort, sourceIP, sourcePort, "")
			if err != nil {
				logger.Printf("StunTest (%s) Failure", host)
			}
			if ret["Resp"].(bool) {
				stunHost = host
				break
			}
		}
	}
	if stunHost == "" {
		return Blocked, nil, fmt.Errorf("No STUN host responded")
	}

	// Perform Test1 with the chosen STUN server
	ret, err := StunTest(conn, stunHost, stunPort, sourceIP, sourcePort, "")
	if err != nil {
		logger.Printf("StunTest (%s) Failure", stunHost)
	}
	if !ret["Resp"].(bool) {
		return Blocked, ret, nil
	}
	logger.Printf("result: %v\n", ret)

	exIP := ret["ExternalIP"].(string)
	exPort := ret["ExternalPort"].(int)
	changedIP := ret["ChangedIP"].(string)
	changedPort := ret["ChangedPort"].(int)

	var typ NatType
	if exIP == sourceIP {
		changeRequest := ChangeRequest + "0004" + "00000006"
		ret, err = StunTest(conn, stunHost, stunPort, sourceIP, sourcePort, changeRequest)
		if err != nil {
			return "", nil, err
		}
		if ret["Resp"].(bool) {
			typ = OpenInternet
		} else {
			typ = SymmetricUDPFirewall
		}
	} else {
		changeRequest := ChangeRequest + "0004" + "00000006"
		ret, err = StunTest(conn, stunHost, stunPort, sourceIP, sourcePort, changeRequest)
		if err != nil {
			logger.Printf("StunTest (%s) Failure", stunHost)
		}
		if ret["Resp"].(bool) {
			typ = FullCone
		} else {
			ret, err = StunTest(conn, changedIP, changedPort, sourceIP, sourcePort, "")
			if err != nil {
				logger.Printf("StunTest (%s) Failure", stunHost)
			}
			if !ret["Resp"].(bool) {
				typ = ChangedAddressError
			} else {
				if exIP == ret["ExternalIP"].(string) && exPort == ret["ExternalPort"].(int) {
					changePortRequest := ChangeRequest + "0004" + "00000002"
					ret, err = StunTest(conn, changedIP, stunPort, sourceIP, sourcePort, changePortRequest)
					if err != nil {
						logger.Printf("StunTest (%s) Failure", stunHost)
					}
					if ret["Resp"].(bool) {
						typ = RestrictNAT
					} else {
						typ = RestrictPortNAT
					}
				} else {
					typ = SymmetricNAT
				}
			}
		}
	}
	return typ, ret, nil
}

// GetIPInfo gets the NAT type, external IP and external port
func GetIPInfo(sourceIP string, sourcePort int, stunHost string, stunPort int) (NatType, string, int, error) {
	// Setup UDP connection
	addr := net.UDPAddr{
		IP:   net.ParseIP(sourceIP),
		Port: sourcePort,
	}
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		return "", "", 0, err
	}
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))

	// Get NAT type
	natType, nat, err := GetNATType(conn, sourceIP, sourcePort, stunHost, stunPort)
	if err != nil {
		return "", "", 0, err
	}

	externalIP, _ := nat["ExternalIP"].(string)
	externalPort, _ := nat["ExternalPort"].(int)

	return natType, externalIP, externalPort, nil
}
