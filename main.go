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
		case ConnectionClose:
			return
		// Ping
		case Ping:
			frame.Opcode = 10
			fallthrough
		case ContinuationFrame:
			fallthrough

		// Text/Binary Frame
		case TextFrame, BinaryFrame:
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
