/*
 * Copyright (c) 2013 Vladimir Blaskov
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package whois

import (
	"fmt"
	"io/ioutil"
	"net"
	"strings"
	"time"
)

const (
	WHOIS_DOMAIN = ".whois-servers.net"
	WHOIS_PORT   = "43"
)

func Whois(query string) (result string, err error) {

	host := findHostPort(query)
	
	if strings.HasSuffix(strings.ToLower(query), ".com") {
		query = fmt.Sprintf("=%s", query)
	}

	result, err = WhoisByServer(query, host)

	return
}

func WhoisByServer(domain string, server string) (result string, err error) {
	var buffer []byte
	
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, WHOIS_PORT), 3*time.Second)
	if err != nil {
		return
	}
	conn.SetReadDeadline(time.Now().Add(time.Second * 2))
	fmt.Fprintf(conn, "%s\r\n", domain)

	buffer, err = ioutil.ReadAll(conn)
	if err != nil {
		return
	}

	result = string(buffer[:])

	return
}

func findHostPort(query string) (host string) {

	fields := strings.Split(query, ".")
	tld := fields[len(fields)-1]

	host = fmt.Sprint(tld, WHOIS_DOMAIN)

	return
}
