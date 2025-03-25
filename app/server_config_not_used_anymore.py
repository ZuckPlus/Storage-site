from app import create_app  #don't care to write documentation for this
#I use AI to write documentation for my code lol

import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
logger.info("Starting the Storage System application")

app = create_app()

if __name__ == "__main__":
    # Using threading=True to enable concurrent request handling
    # This allows multiple users to upload files simultaneously
    logger.info("Running server with threading enabled")
    
    # For local development/testing
    app.run(host="10.200.40.184", port=3240, debug=False, threaded=True)
    
    # For production/local network:
    # app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)

    #10.200.40.184 is the IP address of the server
    #3240 is the port number
    #debug=True is to enable debug mode
    #this is for development purposes
    #when deploying, set debug=False
    #and set host to 0.0.0.0 to allow external access
    
#local host 127.0.0.1:5000

"""
Local network deployment notes:
1. Use the second configuration with host="0.0.0.0" to make the server 
   accessible from other computers on your local network
2. Find your computer's local IP address (e.g., 192.168.1.100) using 'ipconfig' on Windows
3. Other devices on your network can access the application at:
   http://your-local-ip:5000 (e.g., http://192.168.1.100:5000)
4. Ensure your firewall allows incoming connections on port 5000
"""