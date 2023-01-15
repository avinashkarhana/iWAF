import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow.keras as keras
from tensorflow.keras.models import load_model
import pandas as pd
import re
from .SQLiVectorizer import SQLiVectorizer

class Intelligent:
    modelFolderPath = "./iwaf/intelligent/"
    mymodel = load_model(modelFolderPath + 'binary_crossEntropy@adam-Final-SQLI-Model.h5')
    vectorizer = SQLiVectorizer()
    vectorize =  vectorizer.Vectorize
    
    def predictSqliAttack(self,input_val=0,verbose=False):
        def clean_data(inp):
            inp = str(inp)
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
        zip = False
        if input_val == 0:
            zip = True
            out(beautify+"\nEnter 0 anytime to exit!\n"+beautify) 
            input_val = input("Give me some data to work on : \n")
            out(beautify)

        if input_val == '0':
            repeat = False    
        
        input_val = clean_data(input_val)
        clr_str = input_val

        # Vectorization
        input_val = self.vectorize(input_val)
        # drop the first column of the vectorized data df
        input_val = input_val.drop(input_val.columns[0], axis=1)
        result = self.mymodel.predict(input_val)
        out(beautify) 

        if repeat == True and zip == True :
            if result > 0.5:
                print(result,"ALERT :::: This can be SQL injection")
            elif result <= 0.5:
                print(result,"It seems to be safe") 
            out(beautify)
            self.predictSqliAttack()
        else:
            #if result>0.5:print(clr_str)
            return(result)
    