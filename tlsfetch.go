package main

import(
    "net"
    "fmt"
    "flag"
    "crypto/tls"
    "strings"
    "io/ioutil"
    "time"
    "crypto/x509"
)
var verbose bool
var checkSSL bool
var checkSig bool
var checkAlg bool
var checkCiphers bool
var displayAuth bool

type Result struct {
    Ip string
    Port string
    Ciphers []uint16
    Subject string
    SigAlg x509.SignatureAlgorithm
    PubKeyAlg string
    Issuer string
    SSLv2 bool
    SSLv3 bool
}

var sigs = [...]string {
    "Unknown Signature Algorithm",
    "MD2 With RSA",
    "MD5 With RSA",
    "SHA1 With RSA",
    "SHA256 With RSA",
    "SHA384 With RSA",
    "SHA512 With RSA",
    "DSA With SHA1",
    "DSA With SHA256",
    "ECDSA With SHA1",
    "ECDSA With SHA256",
    "ECDSA With SHA384",
    "ECDSA With SHA512",
}

func inc(ip net.IP) {
    for j := len(ip)-1; j>=0; j-- {
        ip[j]++
        if ip[j] > 0 {
            break
        }
    }
}

func parseRange(targetR string) [] string {
    ip, ipnet, err := net.ParseCIDR(targetR)
    if err != nil {
        fmt.Println(err)
        return nil
    }
    var ips [] string

    for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
        ips = append(ips,ip.String())
    }
    return ips
}

func makeConnection(ip string, port string, maxv uint16, ciphers bool) (*tls.Conn,error) {
    target := ip+":"+port
    conn, err := tls.DialWithDialer(&net.Dialer{Timeout:time.Duration(5 * time.Second)},"tcp", target, &tls.Config{
        MaxVersion:maxv,
        InsecureSkipVerify:true,
    })

    if conn != nil {
        defer conn.Close()
    }
    return conn,err

}

func fetchCert(ip string,port string) (Result,error) {
    var res Result

    //test SSLv2 and SSLv3
    if checkSSL == true {
        _,err := makeConnection(ip,port,tls.VersionSSL30,false)
        if err != nil {
            if strings.Index(err.Error(),"selected unsupported protocol version") > -1 {
                res.SSLv3 = true
            } else {
                res.SSLv3 = false
            }
        } else {
            res.SSLv3 = true
        }
    }

    conn,err := makeConnection(ip,port,0,false)

    if err != nil {
        return res,err
    } else {
        res.Subject = conn.ConnectionState().PeerCertificates[0].Subject.CommonName
        res.Ip = ip
        res.Port = port
        res.SigAlg = conn.ConnectionState().PeerCertificates[0].SignatureAlgorithm
        res.Issuer = conn.ConnectionState().PeerCertificates[0].Issuer.CommonName
        return res,nil
    }
}

func parseInputFile(input string) [] string {
    var targets []string

    data, err := ioutil.ReadFile(input)
    if err != nil {
        fmt.Println("Input file not found")
        return nil
    }

    for _, line := range strings.Split(string(data),"\n") {
        if strings.Index(line,"/") > -1 {
            targets = append(targets, parseRange(line)...)
        } else {
            targets = append(targets, line)
        }
    }
    return targets
}

func checkTargets(targets []string, ports []string) {
    resc, errc := make(chan Result), make(chan error)
    for _,val := range targets{
        for _,port := range ports{
            go func(ip string,port string) {
                out,err := fetchCert(ip,port)
                if err != nil {
                    errc <- err
                    return
                }
                resc <- out
            }(val,port)
        }
    }

    for i := 0; i < len(targets)*len(ports); i++ {
        select {
            case res := <-resc:
                if displayAuth == true {
                    fmt.Printf("%s:%s - %s - Signed: %s\n",res.Ip,res.Port,res.Subject,res.Issuer)
                } else {
                    fmt.Printf("%s:%s - %s\n",res.Ip,res.Port,res.Subject)
                }
                if checkSSL == true {
                    fmt.Printf("SSLv3 Supported: %t\n",res.SSLv3)
                }
                if checkSig == true {
                    if res.SigAlg < 4 {
                        fmt.Printf("Signature Alg: %s [WEAK]\n",sigs[res.SigAlg])
                    } else {
                        fmt.Printf("Signature Alg: %s\n",sigs[res.SigAlg])
                    }
                }
                if checkCiphers == true {
                    fmt.Printf("Supported Ciphers: ")
                }
            case err := <-errc:
                if verbose == true {
                    fmt.Println(err)
                }
        }
    }
}

func main(){
    targetPtr := flag.String("t", "", "Target IP or Range")
    targetListPtr := flag.String("iL","","A Local file containing IP addresses and/or Ranges")
    verbosePtr := flag.Bool("v", false, "Display errors (verbose)")
    portPtr := flag.String("p","443","The ports to try connections. Specify comma seperated list")
    checkSSLPtr := flag.Bool("ssl",false,"Check if SSLv2 and SSLv3 are supported")
    checkSigsPtr := flag.Bool("sig",false,"Check if signatures and ciphers used")
    displayAuthPtr := flag.Bool("auth",false,"Display the signing authority (check for self-signed)")

    flag.Parse()
    var targets []string
    verbose = *verbosePtr

    if strings.Index(*targetPtr,"/") > -1 {
        targets = parseRange(*targetPtr)
    } else {
        targets = []string{*targetPtr}
    }

    if *targetListPtr != "" {
        targets = parseInputFile(*targetListPtr)
    }
    checkSSL = *checkSSLPtr
    checkSig = *checkSigsPtr
    displayAuth = *displayAuthPtr

    ports := strings.Split(*portPtr,",")
    checkTargets(targets,ports)
}
