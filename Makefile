.PHONY: listen dial

listen:
	@sudo go run test/main.go -mode listen 
dial:
	@sudo go run test/main.go -mode dial 
