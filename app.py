from flask import Flask, request, render_template_string, jsonify
import monitor

app = Flask(__name__)

@app.route('/')
def home():
    return render_template_string(open('templates/template.html').read())

@app.route('/monitoraggio', methods=['GET'])
def monitoraggio_endpoint():
    query = request.args.get('query', 'country:"IT" city:"Castelnuovo della Daunia"')
    print(f"Running query: {query}") 
    try:
        monitor.monitoraggio(query)
        return jsonify({"message": "Monitoraggio eseguito", "query": query})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
