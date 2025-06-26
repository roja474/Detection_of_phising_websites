import numpy as np
from flask import Flask, request, jsonify, render_template
import pickle
import inputScript
import joblib

app = Flask(__name__)
model = joblib.load(open('Phishing websites.pkl', 'rb'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/predict', methods=['GET', 'POST'])
def predict():
    if request.method == 'POST':
        url = request.form.get('URL')
        if not url:
            return render_template('predict.html', prediction_text='Error: URL is required', url='predict')
        
        try:
            checkprediction = inputScript.Phishing_Website_Detection(url)
            # Reshape the input data to a 2D array
            checkprediction = np.array(checkprediction).reshape(1, -1)
            prediction = model.predict(checkprediction)
            output = prediction[0]
            if output == 1:
                pred = "You are safe!! This is a Legitimate Website."
            else:
                pred = "You are on the wrong site. Be cautious!"
            return render_template('predict.html', prediction_text=pred, url=url)
        except Exception as e:
            return render_template('predict.html', prediction_text='An error occurred: {}'.format(e), url=url)
    else:
        return render_template('predict.html', prediction_text='Error: Invalid request method', url='predict')

@app.route('/predict_api', methods=['POST'])
def predict_api():
    try:
        data = request.get_json(force=True)
        if not data:
            raise ValueError("Invalid JSON data")
        input_array = np.array(list(data.values()))
        # Reshape the input data to a 2D array
        input_array = input_array.reshape(1, -1)
        prediction = model.predict(input_array)
        output = prediction[0]
        return jsonify({'output': output})
    except ValueError as e:
        # Handle invalid JSON data or data format errors
        return jsonify({'error': str(e)}), 400
    except Exception as e:# Handle any other exceptions raised during prediction
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)