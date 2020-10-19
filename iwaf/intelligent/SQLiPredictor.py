import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'
import tensorflow.keras as keras
from tensorflow.keras.models import load_model
import pickle
import pandas as pd
import re

class Intelligent:

    def NewStringVectorizer(self,inp=''): # can take df or string
        import pandas as pd
        import re
        def Newvectorizer(df):
            def num_SQLI_key(df):###############################SQL keyword count##########################
                SQL=["ALL","ADD CONSTRAINT","ALTER COLUMN","ALTER TABLE","AND","ANY","AS","ASC","BACKUP DATABASE","BETWEEN","CASE","CHECK","COLUMN","CONSTRAINT","OPENROWSET","CREATE","INDEX","OR REPLACE VIEW","TABLE","PROCEDURE","UNIQUE INDEX","VIEW","DATABASE","DEFAULT","DELETE","DESC","DECLARE","DISTINCT","DROP COLUMN","DROP CONSTRAINT","DROP DATABASE","DROP DEFAULT","DROP INDEX","DROP TABLE","DROP VIEW","EXEC","EXISTS","FOREIGN KEY","FROM","FULL OUTER JOIN","GROUP BY","HAVING","IN","INDEX","INNER JOIN","INSERT INTO","INSERT INTO SELECT","SELECT USER","IS NULL","IS NOT NULL","LEFT JOIN","LIKE","LIMIT","NOT","NOT NULL","OR","ORDER BY","OUTER JOIN","PRIMARY KEY","PROCEDURE","RIGHT JOIN","ROWNUM","SELECT","DISTINCT","OUTFILE","INTO OUTFILE","SET","TOP","TRUNCATE TABLE","UNION","UNIQUE","UPDATE","VALUES","VIEW","WHERE","LOAD DATA","INFILE","CONCAT", "LOAD_FILE"]
                def countkey(k,r):
                    symbols=['~','`','!','@','#','$','%','^','&','*','(',')','-','_','+','=','{','}','[',']','|','\\','/',':',';','"',"'",'<','>',',','.','?']
                    rr=r['Sentence']
                    for j in symbols:
                        rr=rr.replace('  ',' ')
                        rr=rr.replace(j,' '+j+' ')
                        rr=rr.replace('  ',' ')
                    rr=" "+rr+" "
                    rr=rr.lower()
                    return rr.count(' '+k.lower()+' ') + rr.count(' '+k+' ')
                for a in SQL:
                    df[a]=df.apply (lambda row: countkey(a,row), axis=1)
                return df

            def num_unsual_comb(df):###############################unusual combo count##########################
                combi_regexes={
                        "Number'":r"\d+'",
                        "+Number,":r"\+\d+,",
                        "@@":r"@@[a-zA-Z]",
                        "Number--":r"\d+--",
                        "Alphabets--":r"[a-zA-Z]+--",
                        '%NumberAlphabet':r"%\d+[a-zA-Z]*",
                        '0x2fEncoded':r"0x\d+([a-zA-Z]|)",
                        'comment multiline':r"(\\/*)|(\*\/)",
                        'comment mltiline with Specail MYSQL command': r"\/\*! *\d+",
                        'always true ans such conditions': r"(\"|')(( *\))|) ((or)|(OR)) ((\d+(=|>|<|!=|<>)\d+)|([a-zA-Z]+=[a-zA-Z]+))(( )|)(((--)|(\/\*)|(#))|)",

                        }
                def countcombo(k,r):
                    return len(re.findall(k, r['Sentence']))
                for a in combi_regexes:
                    df[a]=df.apply (lambda row: countcombo(combi_regexes[a],row), axis=1)
                return df
            
            def num_symbols(df):
                symbols=['~','`','!','@','#','$','%','^','&','*','(',')','-','_','+','=','{','}','[',']','|','\\','/',':',';','"',"'",'<','>',',','.','?']
                def countsymbols(k,r):
                    rr=r['Sentence']
                    rr=" "+rr+" "
                    rr=rr.lower()
                    return  rr.count(k)
                for a in symbols:
                    df[a]=df.apply (lambda row: countsymbols(a,row), axis=1)
                return df

            #calculate length
            df['rlen'] = df['Sentence'].str.split(" ").str.join("").str.len()
            df.dropna(inplace=True) 
            #count keywords
            df=num_SQLI_key(df)
            #count Unusual combos
            df=num_unsual_comb(df)
            #number of Symbols
            df=num_symbols(df)
            return df

        
        qdf = pd.DataFrame({'Sentence':[inp]})
        qdf=Newvectorizer(qdf)
        qdf=qdf[qdf.columns[1:]]
        return qdf



    #mymodel = load_model('./intelligent/Final-SQLI-Model.h5')
    mymodel = load_model('./intelligent/binary_crossentropy@adam-Final-SQLI-Model.h5')
    #myvectorizer = pickle.load(open("./intelligent/Final-SQLI-Vectorizer", 'rb'))
    myvectorizer = NewStringVectorizer
    def predict_sqli_attack(self,input_val=0,verbose=False):
        def clean_data(inp):
            inp=inp.replace('\n', '')
            inp=inp.replace('%20', ' ')
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
        
        input_val=clean_data(input_val)

        '''# Old Vectorizer
        input_val=[input_val]
        input_val=self.myvectorizer.transform(input_val).toarray()
        '''

        # New Vectorizer
        input_val=self.myvectorizer(inp=input_val)

        result=self.mymodel.predict(input_val)
        out(beautify) 

        if repeat == True and zip == True :
            if result>0.5:
                print(result,"ALERT :::: This can be SQL injection")
            elif result<=0.5:
                print(result,"It seems to be safe") 
            out(beautify)
            self.predict_sqli_attack()
        else:
            return(result)
            out( " Good Bye ")