from flask import Flask, render_template, request, jsonify, send_file
from flask_cors import CORS
import json
import os
from diagnose_website import diagnose_site, generate_technical_observation, diagnose_multiple_sites
from urllib.parse import urlparse
from excel_export import export_single_result_to_excel, export_bulk_results_to_excel, export_company_list_to_excel
from google_sheets_export import export_single_result_to_gsheet, export_bulk_results_to_gsheet, export_company_list_to_gsheet
from csv_parser import validate_csv_file
from werkzeug.utils import secure_filename
from bulk_processor import bulk_processor
from email_service import send_email

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
    """List all saved diagnosis results with pagination, search, filter, and sort."""
    try:
        results_dir = 'results'
        os.makedirs(results_dir, exist_ok=True)
        
        # Get query parameters
        page = int(request.args.get('page', 1))
        limit = int(request.args.get('limit', 20))
        search = request.args.get('search', '').strip().lower()
        status_filter = request.args.get('status', '').strip()
        vulnerability_filter = request.args.get('vulnerability', '').strip()
        sort_by = request.args.get('sort', 'date')  # date, domain, status, vulnerabilities
        sort_order = request.args.get('order', 'desc')  # asc, desc
        
        files = []
        load_times = []
        
        for filename in os.listdir(results_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(results_dir, filename)
                try:
                    # Get file stats
                    stat = os.stat(filepath)
                    
                    # Read the result to get basic info
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    
                    domain = data.get('domain', '')
                    tech = data.get('tech', 'Unknown')
                    status = data.get('status', 'unknown')
                    load_time = data.get('load_time', 'N/A')
                    vulnerability_detected = data.get('vulnerability_detected', False)
                    vulnerabilities_count = len(data.get('vulnerabilities', []))
                    
                    # Collect load times for statistics (only numeric values)
                    if load_time != 'N/A':
                        try:
                            # Extract numeric value from load_time (e.g., "2.3s" -> 2.3)
                            load_time_num = float(load_time.replace('s', '').strip())
                            load_times.append(load_time_num)
                        except:
                            pass
                    
                    files.append({
                        'filename': filename,
                        'url': data.get('url', ''),
                        'domain': domain,
                        'tech': tech,
                        'status': status,
                        'load_time': load_time,
                        'console_error_count': data.get('console_error_count', 0),
                        'vulnerability_detected': vulnerability_detected,
                        'vulnerabilities_count': vulnerabilities_count,
                        'modified': stat.st_mtime
                    })
                except Exception as e:
                    # Skip corrupted files
                    continue
        
        # Apply search filter
        if search:
            files = [f for f in files if search in f['domain'].lower() or search in f['tech'].lower()]
        
        # Apply status filter
        if status_filter:
            files = [f for f in files if f['status'] == status_filter]
        
        # Apply vulnerability filter
        if vulnerability_filter == 'yes':
            files = [f for f in files if f['vulnerability_detected']]
        elif vulnerability_filter == 'no':
            files = [f for f in files if not f['vulnerability_detected']]
        
        # Apply sorting
        if sort_by == 'date':
            files.sort(key=lambda x: x['modified'], reverse=(sort_order == 'desc'))
        elif sort_by == 'domain':
            files.sort(key=lambda x: x['domain'].lower(), reverse=(sort_order == 'desc'))
        elif sort_by == 'status':
            files.sort(key=lambda x: x['status'], reverse=(sort_order == 'desc'))
        elif sort_by == 'vulnerabilities':
            files.sort(key=lambda x: x['vulnerabilities_count'], reverse=(sort_order == 'desc'))
        
        # Calculate statistics
        total_count = len(files)
        with_vulnerabilities = sum(1 for f in files if f['vulnerability_detected'])
        without_vulnerabilities = total_count - with_vulnerabilities
        avg_load_time = sum(load_times) / len(load_times) if load_times else 0
        
        # Apply pagination
        total_pages = (total_count + limit - 1) // limit  # Ceiling division
        start_idx = (page - 1) * limit
        end_idx = start_idx + limit
        paginated_files = files[start_idx:end_idx]
        
        return jsonify({
            'results': paginated_files,
            'pagination': {
                'page': page,
                'limit': limit,
                'total': total_count,
                'total_pages': total_pages,
                'has_next': page < total_pages,
                'has_prev': page > 1
            },
            'statistics': {
                'total': total_count,
                'with_vulnerabilities': with_vulnerabilities,
                'without_vulnerabilities': without_vulnerabilities,
                'avg_load_time': f"{avg_load_time:.1f}s" if avg_load_time > 0 else "N/A"
            }
        })
    
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Results list error: {error_trace}")
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


@app.route('/results/<filename>', methods=['DELETE'])
def delete_result(filename):
    """Delete a specific diagnosis result."""
    try:
        # Security: prevent directory traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        filepath = os.path.join('results', filename)
        
        if not os.path.exists(filepath):
            return jsonify({'error': 'Result not found'}), 404
        
        os.remove(filepath)
        return jsonify({'success': True, 'message': 'Result deleted successfully'})
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/export/excel/<filename>', methods=['GET'])
def export_result_to_excel(filename):
    """Export a single diagnosis result to Google Sheet."""
    try:
        # Security: prevent directory traversal
        if '..' in filename or '/' in filename or '\\' in filename:
            return jsonify({'error': 'Invalid filename'}), 400
        
        json_filepath = os.path.join('results', filename)
        
        if not os.path.exists(json_filepath):
            return jsonify({'error': 'Result not found'}), 404
        
        # Read JSON data
        with open(json_filepath, 'r') as f:
            result_data = json.load(f)
        
        # Export to Google Sheet
        try:
            sheet_url = export_single_result_to_gsheet(result_data)
        except FileNotFoundError:
             return jsonify({'error': 'Google Sheets authentication failed: credentials.json not found on server.'}), 500
        except Exception as e:
             return jsonify({'error': f'Google Sheets API error: {str(e)}'}), 500
        
        return jsonify({'success': True, 'sheet_url': sheet_url})
    
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Google Sheets export error: {error_trace}")
        return jsonify({'error': f'Export failed: {str(e)}'}), 500


@app.route('/export/excel/bulk', methods=['GET'])
def export_all_results_to_excel():
    """Export all saved diagnosis results to a single Google Sheet."""
    try:
        results_dir = 'results'
        os.makedirs(results_dir, exist_ok=True)
        
        # Collect all JSON results
        results_list = []
        for filename in os.listdir(results_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(results_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                        results_list.append(data)
                except Exception as e:
                    # Skip corrupted files
                    continue
        
        if not results_list:
            return jsonify({'error': 'No results found to export'}), 404
        
        # Export to Google Sheet
        try:
            sheet_url = export_bulk_results_to_gsheet(results_list)
        except FileNotFoundError:
             return jsonify({'error': 'Google Sheets authentication failed: credentials.json not found on server.'}), 500
        except Exception as e:
             return jsonify({'error': f'Google Sheets API error: {str(e)}'}), 500
        
        return jsonify({'success': True, 'sheet_url': sheet_url})
    
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Bulk export error: {error_trace}")
        return jsonify({'error': f'Bulk export failed: {str(e)}'}), 500


@app.route('/download-excel/all', methods=['GET'])
def download_full_company_list():
    """Export all company diagnosis results to Google Sheet with complete details."""
    try:
        results_dir = 'results'
        os.makedirs(results_dir, exist_ok=True)
        
        # Collect all JSON results with full data
        results_list = []
        for filename in os.listdir(results_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(results_dir, filename)
                try:
                    stat = os.stat(filepath)
                    with open(filepath, 'r') as f:
                        data = json.load(f)
                    # Add modified timestamp for date formatting
                    data['modified'] = stat.st_mtime
                    results_list.append(data)
                except Exception as e:
                    # Skip corrupted files
                    continue
        
        if not results_list:
            return jsonify({'error': 'No results found to export'}), 404
        
        # Export to Google Sheet
        try:
            sheet_url = export_company_list_to_gsheet(results_list)
        except FileNotFoundError:
             return jsonify({'error': 'Google Sheets authentication failed: credentials.json not found on server.'}), 500
        except Exception as e:
             return jsonify({'error': f'Google Sheets API error: {str(e)}'}), 500
             
        return jsonify({'success': True, 'sheet_url': sheet_url})
    
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Full company list export error: {error_trace}")
        return jsonify({'error': f'Export failed: {str(e)}'}), 500


@app.route('/download-excel/filtered', methods=['POST'])
def download_filtered_company_list():
    """Export filtered company diagnosis results to Google Sheet with complete details."""
    try:
        data = request.get_json() or {}
        
        # Get filter parameters from request
        search = data.get('search', '').strip().lower()
        status_filter = data.get('status', '').strip()
        vulnerability_filter = data.get('vulnerability', '').strip()
        
        results_dir = 'results'
        os.makedirs(results_dir, exist_ok=True)
        
        # Collect all JSON results with full data
        all_results = []
        for filename in os.listdir(results_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(results_dir, filename)
                try:
                    stat = os.stat(filepath)
                    with open(filepath, 'r') as f:
                        result_data = json.load(f)
                    # Add modified timestamp for date formatting
                    result_data['modified'] = stat.st_mtime
                    all_results.append(result_data)
                except Exception as e:
                    # Skip corrupted files
                    continue
        
        if not all_results:
            return jsonify({'error': 'No results found to export'}), 404
        
        # Apply filters (same logic as /results endpoint)
        filtered_results = []
        
        for result in all_results:
            domain = result.get('domain', '').lower()
            tech = result.get('tech', 'Unknown').lower()
            status = result.get('status', 'unknown')
            vulnerability_detected = result.get('vulnerability_detected', False)
            
            # Apply search filter
            if search:
                if search not in domain and search not in tech:
                    continue
            
            # Apply status filter
            if status_filter:
                if status != status_filter:
                    continue
            
            # Apply vulnerability filter
            if vulnerability_filter == 'yes':
                if not vulnerability_detected:
                    continue
            elif vulnerability_filter == 'no':
                if vulnerability_detected:
                    continue
            
            filtered_results.append(result)
        
        if not filtered_results:
            return jsonify({'error': 'No results match the current filters'}), 404
        
        # Export to Google Sheet
        try:
            sheet_url = export_company_list_to_gsheet(filtered_results)
        except FileNotFoundError:
             return jsonify({'error': 'Google Sheets authentication failed: credentials.json not found on server.'}), 500
        except Exception as e:
             return jsonify({'error': f'Google Sheets API error: {str(e)}'}), 500
             
        return jsonify({'success': True, 'sheet_url': sheet_url})
    
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Filtered company list export error: {error_trace}")
        return jsonify({'error': f'Export failed: {str(e)}'}), 500


@app.route('/upload-csv', methods=['POST'])
def upload_csv():
    """Handle CSV file upload and parse URLs."""
    try:
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        
        # Check if file is selected
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Check file extension
        if not file.filename.lower().endswith('.csv'):
            return jsonify({'error': 'Invalid file type. Please upload a CSV file.'}), 400
        
        # Read file content
        file_content = file.read()
        
        if not file_content:
            return jsonify({'error': 'File is empty'}), 400
        
        # Validate and parse CSV
        is_valid, error_message, data = validate_csv_file(file_content, secure_filename(file.filename))
        
        if not is_valid:
            return jsonify({'error': error_message}), 400
        
        # Return parsed data
        return jsonify({
            'success': True,
            'message': f'CSV uploaded successfully: {data["metadata"]["filename"]} ({data["metadata"]["url_count"]} URLs found)',
            'data': data
        })
    
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"CSV upload error: {error_trace}")
        return jsonify({
            'error': f'CSV upload failed: {str(e)}',
            'details': error_trace if os.environ.get('FLASK_DEBUG') else None
        }), 500


@app.route('/process-bulk-urls', methods=['POST'])
def process_bulk_urls():
    """Start bulk processing job for multiple URLs from uploaded CSV."""
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({'error': 'No URLs provided'}), 400
        
        if not isinstance(urls, list):
            return jsonify({'error': 'URLs must be a list'}), 400
        
        if len(urls) > 100:  # Limit to prevent abuse
            return jsonify({'error': 'Maximum 100 URLs allowed per bulk processing'}), 400
        
        # Create background job
        generate_observations = data.get('generate_observations', False)
        job_id = bulk_processor.create_job(urls, generate_observations)
        
        return jsonify({
            'success': True,
            'job_id': job_id,
            'message': f'Bulk processing started for {len(urls)} URLs',
            'total_urls': len(urls)
        })
    
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Bulk processing error: {error_trace}")
        return jsonify({
            'error': f'Bulk processing failed: {str(e)}',
            'details': error_trace if os.environ.get('FLASK_DEBUG') else None
        }), 500


@app.route('/bulk-status/<job_id>', methods=['GET'])
def get_bulk_status(job_id):
    """Get status of a bulk processing job."""
    try:
        job = bulk_processor.get_job_status(job_id)
        
        if not job:
            return jsonify({'error': 'Job not found'}), 404
        
        # Calculate progress percentage
        progress_percent = 0
        if job['total'] > 0:
            progress_percent = int((job['completed'] / job['total']) * 100)
        
        return jsonify({
            'job_id': job_id,
            'status': job['status'],
            'total': job['total'],
            'completed': job['completed'],
            'successful': job['successful'],
            'failed': job['failed'],
            'progress_percent': progress_percent,
            'current_url': job.get('current_url'),
            'started_at': job['started_at'],
            'completed_at': job.get('completed_at'),
            'errors': job.get('errors', [])
        })
    
    except Exception as e:
        return jsonify({'error': f'Failed to get job status: {str(e)}'}), 500
@app.route('/api/send-email', methods=['POST'])
def send_personalized_email():
    """Send a personalized email using the "Sniper" template."""
    try:
        data = request.get_json()
        
        # Required fields
        recipient_email = data.get('recipient_email')
        name = data.get('name', 'there')
        domain = data.get('domain')
        industry = data.get('industry', 'your')
        console_errors = data.get('console_errors', '0')
        load_time = data.get('load_time', 'N/A')
        signature = data.get('signature', 'The Team')
        
        if not recipient_email or not domain:
            return jsonify({'error': 'recipient_email and domain are required'}), 400
            
        # Format the template
        subject = f"Technical debt on {domain} (AngularJS 1.x)"
        body = f"""Hi {name},

My automated scanner flagged {domain} while analyzing legacy frameworks in the {industry} sector.

It looks like you're still running AngularJS 1.5 in production. We also caught [{console_errors}] console errors on the homepage that are likely impacting your load times ([{load_time}]).

I’m not trying to sell you a new website. But if you need a specialized team to handle the migration to React/Vue without breaking your database connections, that is exactly what we do.

Open to a 10-min technical audit?

{signature}"""

        # Send the email
        send_email(recipient_email, subject, body)
        
        return jsonify({'success': True, 'message': 'Email sent successfully'})
        
    except Exception as e:
        import traceback
        error_trace = traceback.format_exc()
        print(f"Send email error: {error_trace}")
        return jsonify({
            'error': f'Failed to send email: {str(e)}',
            'details': error_trace if os.environ.get('FLASK_DEBUG') else None
        }), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

