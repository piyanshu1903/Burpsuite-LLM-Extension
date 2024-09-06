from flask import Flask, jsonify, request,render_template
from openai import prompt

# app = Flask(__name__)
app = Flask(__name__, template_folder='.')

@app.route('/halted')
def halted_display():
   return render_template('halted.html', methods=['GET'])

@app.route('/flag_red',methods=['POST'])
def flag_red():
    try:
        # Get JSON data from the request body
        data = request.json
        
        # Extracting data from the JSON object
        url = data.get('url')
        print("Flag Red")
        
        return jsonify({"result": "flagged"}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
    
@app.route('/check_flag',methods=['POST'])
def check_flag():
    try:
        # Get JSON data from the request body
        data = request.json
        
        # Extracting data from the JSON object
        url = data.get('url')
        status=""
        if("bwapp" in url):
            print("Flagged Red")
            status="threat"
        else:
            status="clear"

        
        return jsonify({"result": status}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400
   

@app.route('/openai', methods=['POST'])
def openai_route():
    try:
        # Get JSON data from the request body
        data = request.json
        
        # Extracting data from the JSON object
        url = data.get('url')
        Request = data.get('Request')
        body = data.get('body')

        # Perform operations using OpenAI
        result = prompt(url, Request, body)
        
        return jsonify({"result": result}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    # Change host and port as per your requirements
    app.run(host='127.0.0.1', port=8083, debug=False)
