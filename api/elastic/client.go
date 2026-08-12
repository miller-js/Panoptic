package main

import (
	"fmt"
	"github.com/elastic/go-elasticsearch/v8"
)

type ElasticClient struct {
}

func main() {
	client, err := elasticsearch.NewTypedClient(elasticsearch.Config{
		Addresses: []string{"http://localhost:9200"}
	}

	if err != nil {
		fmt.Println(err)
	}




)
}