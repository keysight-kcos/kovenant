package main

import (
	"fmt"
	"net/http"
)

func res(w http.ResponseWriter, req *http.Request) {
	fmt.Fprintf(w, "Responding.")
}

func main() {
	http.HandleFunc("/", res)

	http.ListenAndServe(":80", nil)
}
