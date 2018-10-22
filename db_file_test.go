package main

import (
	"io/ioutil"
	"log"
	"testing"

	proto "github.com/golang/protobuf/proto"
)

func TestWriteDB01(t *testing.T) {
	test := &DB{
		Hosts: []*Record{
			&Record{
				Pattern: "aaa.com",
				Data:    "3.3.3.3",
			},
			&Record{
				Pattern: "bbb.com",
				Data:    "2.2.2.2",
			},
		},
	}
	data, err := proto.Marshal(test)
	if err != nil {
		log.Fatal("marshaling error: ", err)
	}
	err = ioutil.WriteFile("data.bin", data, 0644)
	if err != nil {
		log.Fatal("write error: ", err)
	}
	log.Println(data)
}

//go test *.go -v -run TestWriteDB02
func TestWriteDB02(t *testing.T) {
	var err error
	test := &DB{
		Hosts: []*Record{
			&Record{
				Pattern: "aaa.com",
				Data:    "3.3.3.3",
			},
			&Record{
				Pattern: "bbb.com",
				Data:    "2.2.2.2",
			},
		},
		BlockName: []string{"a1.com", "a2.com"},
		BlockIp:   []string{"1.1.1.1", "2.2.*"},
		Forward: []*Finder{
			&Finder{
				Name:   []string{"8.8.8.8:53", "1.2.4.8:53"},
				Domain: []string{"baidu.com"},
			},
			&Finder{
				Name:   []string{"1.1.1.1:53"},
				Domain: []string{"google.com"},
			},
		},
		Doh: []*Finder{
			&Finder{
				Name:   []string{"https://dns.google.com/resolve?name={name}&type={type}"},
				Domain: []string{"www.163.com"},
			},
		},
	}
	err = Save("data.bin", test)
	if err != nil {
		log.Fatal("write error: ", err)
	}

}

func TestReadDB02(t *testing.T) {
	var data DB
	var err error
	err = Load("data.bin", &data)
	if err != nil {
		log.Fatal("read error: ", err)
	}
	log.Printf("%+v", data)
}
