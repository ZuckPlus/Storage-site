from app import create_app 
import logging 
import os 
 
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
    logger.info("Running server with threading enabled") 
    app.run(host="10.200.40.184", port=3240, debug=True, threaded=True) 
