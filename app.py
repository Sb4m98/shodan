from flask import Flask, request, render_template_string, jsonify, redirect
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
        return redirect("https://app.powerbi.com/reportEmbed?reportId=8e5f6b6b-d2b3-4d78-9cd1-e26275961b21&autoAuth=true&ctid=e99647dc-1b08-454a-bf8c-699181b389ab")

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    app.run(host='0.0.0.0', port=5000)
