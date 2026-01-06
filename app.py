from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
import json
import os
from diagnose_website import diagnose_site, generate_technical_observation
from urllib.parse import urlparse

app = Flask(__name__)
CORS(app)  # Enable CORS to allow requests from different ports/origins

def get_safe_filename(url):
    """Convert URL to safe filename."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc or parsed.path.split('/')[0]
        # Remove www. and replace dots/special chars
        domain = domain.replace('www.', '').replace('.', '_').replace('/', '_').replace(':', '_')
        # Remove any remaining invalid characters
        domain = ''.join(c if c.isalnum() or c in ('_', '-') else '_' for c in domain)
        # Limit length
        domain = domain[:50]
        return f"diagnosis_{domain}.json"
    except:
        # Fallback to timestamp if parsing fails
        import time
        return f"diagnosis_{int(time.time())}.json"


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/diagnose', methods=['POST'])
def diagnose():
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Ensure URL has protocol
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        
        # Run diagnosis
        try:
            result = diagnose_site(url)
        except Exception as e:
            # Log the error for debugging
            import traceback
            error_trace = traceback.format_exc()
            print(f"Diagnosis error: {error_trace}")
            return jsonify({
                'error': f'Diagnosis failed: {str(e)}',
                'details': error_trace if os.environ.get('FLASK_DEBUG') else None
            }), 500
        
        # Generate technical observation if vulnerabilities detected
        if result.get("vulnerability_detected", False):
            try:
                observation = generate_technical_observation(result)
                if observation:
                    result["technical_observation"] = observation
            except Exception as e:
                # Don't fail if observation generation fails
                print(f"Observation generation failed: {str(e)}")
        
        # Save to file with URL-based name
        filename = get_safe_filename(url)
        filepath = os.path.join('results', filename)
        
        # Create results directory if it doesn't exist
        os.makedirs('results', exist_ok=True)
        
        try:
            with open(filepath, 'w') as f:
                json.dump(result, f, indent=2)
        except Exception as e:
            print(f"Failed to save result: {str(e)}")
            # Continue even if save fails
        
        result['output_file'] = filename
        result['output_path'] = filepath
        
        return jsonify(result)
    
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Request error: {error_trace}")
        return jsonify({
            'error': str(e),
            'details': error_trace if os.environ.get('FLASK_DEBUG') else None
        }), 500


@app.route('/results', methods=['GET'])
def list_results():
    """List all saved diagnosis results."""
    try:
        results_dir = 'results'
        os.makedirs(results_dir, exist_ok=True)
        
        files = []
        for filename in os.listdir(results_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(results_dir, filename)
                try:
                    # Get file stats
                    stat = os.stat(filepath)
                    
                    # Read the result to get basic info
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    
                    files.append({
                        'filename': filename,
                        'url': data.get('url', ''),
                        'domain': data.get('domain', ''),
                        'tech': data.get('tech', 'Unknown'),
                        'status': data.get('status', 'unknown'),
                        'load_time': data.get('load_time', 'N/A'),
                        'console_error_count': data.get('console_error_count', 0),
                        'vulnerability_detected': data.get('vulnerability_detected', False),
                        'vulnerabilities_count': len(data.get('vulnerabilities', [])),
                        'modified': stat.st_mtime
                    })
                except Exception as e:
                    # Skip corrupted files
                    continue
        
        # Sort by modified time (newest first)
        files.sort(key=lambda x: x['modified'], reverse=True)
        
        return jsonify({'results': files})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/results/<filename>', methods=['GET'])
def get_result(filename):
    """Get a specific diagnosis result."""
    try:
        # Security: prevent directory traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        filepath = os.path.join('results', filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Result not found'}), 404
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        
        data['output_file'] = filename
        return jsonify(data)
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

