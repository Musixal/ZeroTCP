.PHONY: listen dial

listen:
	go run test/main.go -mode listen 
dial:
	go run test/main.go -mode dial 
