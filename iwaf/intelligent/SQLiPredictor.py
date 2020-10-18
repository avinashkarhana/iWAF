import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow.keras as keras
from tensorflow.keras.models import load_model
import pickle
class Intelligent:
    #mymodel = load_model('./intelligent/Final-SQLI-Model.h5')
    mymodel = load_model('./intelligent/binary_crossentropy@adam-Final-SQLI-Model.h5')
    #myvectorizer = pickle.load(open("./intelligent/Final-SQLI-Vectorizer", 'rb'))
    myvectorizer = pickle.load(open("./intelligent/New-Final-SQLI-Vectorizer", 'rb'))

    def predict_sqli_attack(self,input_val=0,verbose=False):
        def clean_data(inp):
            inp=inp.replace('\n', '')
            inp=inp.replace('%20', ' ')
            inp=inp.replace('=', ' = ')
            inp=inp.replace('((', ' (( ')
            inp=inp.replace('))', ' )) ')
            inp=inp.replace('(', ' ( ')
            inp=inp.replace(')', ' ) ')
            inp=inp.replace('1 ', 'numeric')
            inp=inp.replace(' 1', 'numeric')
            inp=inp.replace("'1 ", "'numeric ")
            inp=inp.replace(" 1'", " numeric'")
            inp=inp.replace('1,', 'numeric,')
            inp=inp.replace(" 2 ", " numeric ")
            inp=inp.replace(' 3 ', ' numeric ')
            inp=inp.replace(' 3--', ' numeric--')
            inp=inp.replace(" 4 ", ' numeric ')
            inp=inp.replace(" 5 ", ' numeric ')
            inp=inp.replace(' 6 ', ' numeric ')
            inp=inp.replace(" 7 ", ' numeric ')
            inp=inp.replace(" 8 ", ' numeric ')
            inp=inp.replace('1234', ' numeric ')
            inp=inp.replace("22", ' numeric ')
            inp=inp.replace(" 8 ", ' numeric ')
            inp=inp.replace(" 200 ", ' numeric ')
            inp=inp.replace("23 ", ' numeric ')
            inp=inp.replace('"1', '"numeric')
            inp=inp.replace('1"', '"numeric')
            inp=inp.replace("7659", 'numeric')
            inp=inp.replace(" 37 ", ' numeric ')
            inp=inp.replace(" 45 ", ' numeric ')
            return inp

        def out(s):
            if verbose:
                print(s)
        repeat=True
        beautify=''
        for i in range(20):
            beautify+= "="
        zip=False
        if input_val==0:
            zip=True
            out(beautify+"\nEnter 0 anytime to exit!\n"+beautify) 
            input_val=input("Give me some data to work on : ")
            out(beautify)

        if input_val== '0':
            repeat=False    
        
        '''# Old Vectorizer
        input_val=clean_data(input_val)
        input_val=[input_val]
        input_val=self.myvectorizer.transform(input_val).toarray()
        '''

        # New Vectorizer
        input_val=myvectorizer(input_val)

        result=self.mymodel.predict(input_val)
        out(beautify) 

        if repeat == True and zip == True :
            if result>0.5:
                print(result,"ALERT :::: This can be SQL injection")
            elif result<=0.5:
                print(result,"It seems to be safe") 
            out(beautify)
            predict_sqli_attack()
        else:
            return(result)
            out( " Good Bye ")