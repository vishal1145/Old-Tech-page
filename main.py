from app import app
import os

if __name__ == '__main__':
    # Get port from environment variable (Render provides this)
    port = int(os.environ.get('PORT', 5000))
    # Run in production mode (debug=False)
    app.run(host='0.0.0.0', port=port, debug=False)

