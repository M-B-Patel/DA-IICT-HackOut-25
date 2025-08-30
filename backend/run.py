from blockchain import app, wallet, blockchain

if __name__ == '__main__':
    import argparse
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description='Run GHC Blockchain node')
    parser.add_argument('-p', '--port', type=int, default=5000, help='Port to run the node on')
    args = parser.parse_args()
    
    port = args.port
    
    print(f"Starting GHC node on port {port}")
    print(f"Wallet address: {wallet.address}")
    print(f"Genesis block hash: {blockchain.chain[0].hash}")
    
    app.run(host='0.0.0.0', port=port, debug=True)