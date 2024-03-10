package main

import (
	"log"
	"net/http"
)

func wsHandle(w http.ResponseWriter, r *http.Request) {
	ws, err := New(w, r)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	err = ws.Handshake()
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	defer ws.Close()

	for {
		frame, err := ws.Recv()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		switch frame.Opcode {
		case 8:
			return
		// Ping
		case 9:
			frame.Opcode = 10
			fallthrough
		case 0:
			fallthrough

		// Text/Binary Frame
		case 1, 2:
			if err = ws.Send(frame); err != nil {
				log.Println("Error sending", err)
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

	}
}

func main() {
	http.HandleFunc("/", wsHandle)
	http.ListenAndServe(":8000", nil)
}
