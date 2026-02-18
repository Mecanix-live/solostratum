#!/bin/bash

set -e
CERTS_DIR="$(pwd)/certs"
echo ""
echo ""

# Get the server's IP address automatically
SERVER_IP=$(hostname -I | awk '{print $1}')
echo "Creating certificates for Solostratum with CN="$SERVER_IP

if [ "$1" = "--self-signed" ]; then
    # Generate self-signed certs
    openssl req -x509 -newkey rsa:2048 \
        -keyout "$CERTS_DIR/server.key" \
        -out "$CERTS_DIR/server.crt" \
        -days 365 -nodes \
        -subj "/C=US/ST=California/L=San Francisco/O=Solo Stratum/CN="$SERVER_IP
    
    cp "$CERTS_DIR/server.crt" "$CERTS_DIR/miner_custom_cert.crt"
    
    echo "**************************************"
    echo "Self-signed certificates saved in $CERTS_DIR/"
    echo "**************************************"
    echo "IMPORTANT STEP:"
	echo "Open the file miner_custom_cert.crt with a text editor, copy its content, and paste in your miner's custom certificate field."
	echo "If any problem connecting, ensure your host IP for your stratum server is correct --> CN="$SERVER_IP
    echo "**************************************"
    
elif [ "$1" = "--letsencrypt" ]; then
    # Instructions for Let's Encrypt
    echo "=== Let's Encrypt Setup ==="
    echo "1. Install certbot: sudo apt install certbot"
    echo "2. Run: sudo certbot certonly --standalone -d pool.example.com"
    echo "3. Certificates will be in /etc/letsencrypt/live/pool.example.com/"
    echo "4. Configure your solostratum.conf with:"
    echo "   tls_cert_file=/etc/letsencrypt/live/pool.example.com/fullchain.pem"
    echo "   tls_key_file=/etc/letsencrypt/live/pool.example.com/privkey.pem"
    
else
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  --self-signed    Generate self-signed certificates (testing)"
    echo "  --letsencrypt    Instructions for Let's Encrypt (production)"
    echo ""
    echo "For production, we recommend:"
    echo "  1. Use Let's Encrypt for public pools"
    echo "  2. Self-signed only for testing"
fi
echo ""
echo ""
