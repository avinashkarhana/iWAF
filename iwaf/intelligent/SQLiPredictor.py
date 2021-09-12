import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow.keras as keras
from tensorflow.keras.models import load_model
import pandas as pd
import cloudpickle
import re

class Intelligent:
    mymodel = load_model('./intelligent/binary_crossentropy@adam-Final-SQLI-Model.h5')
    myvectorizer = cloudpickle.load(open('./intelligent/New-Final-SQLI-Vectorizer', 'rb'))
    myvectorizer = staticmethod(myvectorizer)
    def predict_sqli_attack(self,input_val=0,verbose=False):
        def clean_data(inp):
            inp = inp.replace('\n', '')
            inp = inp.replace('%20', ' ')
            inp = inp.replace('/', ' ')
            inp = inp.replace('_', ' _ ')
            inp = inp.replace('?', ' ? ')
            inp = inp.replace('.', ' . ')
            inp = inp.replace('=', ' ')
            inp = re.sub(r"\d+", "numeric", inp) 

            return inp

        def out(s):
            if verbose:
                print(s)
        repeat = True
        beautify = ''
        for i in range(20):
            beautify += "="
        zip=False
        if input_val == 0:
            zip = True
            out(beautify+"\nEnter 0 anytime to exit!\n"+beautify) 
            input_val = input("Give me some data to work on : \n")
            out(beautify)

        if input_val == '0':
            repeat = False    
        
        input_val = clean_data(input_val)
        clr_str = input_val

        # Vectorization with New Vectorizer
        input_val = self.myvectorizer(inp=input_val)

        result = self.mymodel.predict(input_val)
        out(beautify) 

        if repeat == True and zip == True :
            if result > 0.5:
                print(result,"ALERT :::: This can be SQL injection")
            elif result <= 0.5:
                print(result,"It seems to be safe") 
            out(beautify)
            self.predict_sqli_attack()
        else:
            #if result>0.5:print(clr_str)
            return(result)