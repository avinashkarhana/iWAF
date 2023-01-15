import pandas as pd
import re
class SQLiVectorizer:
    def Vectorize(self, data):
        if isinstance(data, pd.DataFrame):
            df = data
        elif isinstance(data, str):
            df = pd.DataFrame({'Sentence':[str(data)]})
        else:
            raise TypeError('Data must be a string or a pandas DataFrame')

        ###############################SQL keyword count##########################
        def numOfSqliKeywords(df):
            sqlKeyWords=["ALL","ADD CONSTRAINT","ALTER", "DROP","ALTER COLUMN","ALTER TABLE","AND","ANY","AS","ASC","BACKUP DATABASE","BETWEEN","CASE","CHECK","COLUMN","CONSTRAINT","OPENROWSET","CREATE","INDEX","OR REPLACE VIEW","TABLE","PROCEDURE","UNIQUE INDEX","VIEW","DATABASE","DEFAULT","DELETE","DESC","DECLARE","DISTINCT","DROP COLUMN","DROP CONSTRAINT","DROP DATABASE","DROP DEFAULT","DROP INDEX","DROP TABLE","DROP VIEW","EXEC","EXISTS","FOREIGN KEY","FROM","FULL OUTER JOIN","GROUP BY","HAVING","IN","INDEX","INNER JOIN","INSERT INTO","INSERT INTO SELECT","SELECT USER","IS NULL","IS NOT NULL","LEFT JOIN","LIKE","LIMIT","NOT","NOT NULL","OR","ORDER BY","OUTER JOIN","PRIMARY KEY","PROCEDURE","RIGHT JOIN","ROWNUM","SELECT","DISTINCT","OUTFILE","INTO OUTFILE","SET","TOP","TRUNCATE TABLE","UNION","UNIQUE","UPDATE","VALUES","VIEW","WHERE","LOAD DATA","INFILE","CONCAT", "LOAD_FILE"]
            def countKeyword(keyword,requestString):
                symbols=['~','`','!','@','#','$','%','^','&','*','(',')','-','_','+','=','{','}','[',']','|','\\','/',':',';','"',"'",'<','>',',','?','.']
                for symbol in symbols:
                    requestString = requestString.replace(symbol, ' ' + symbol + ' ')
                    requestString = ' '.join(requestString.split())
                requestString = " " + requestString + " "
                requestString = requestString.lower()
                return requestString.count(' ' + keyword.lower() + ' ') + requestString.count(' ' + keyword + ' ')
            for keyword in sqlKeyWords:
                df[keyword] = df.apply (lambda row: countKeyword(keyword, row['Sentence']), axis=1)
            return df
        
        ##############################unusual combo count##########################
        def numberOfUnusualStringCombinations(df):
            combinationRegex = {
                "Number'":r"\d+'",
                "Number":r"numeric",
                "+Number,":r"\+\d+,",
                "@@":r"@@[a-zA-Z]",
                "Number--":r"\d+--",
                "Alphabets--":r"[a-zA-Z]+--",
                '%NumberAlphabet':r"%\d+[a-zA-Z]*",
                '0x2fEncoded':r"0x\d+([a-zA-Z]|)",
                'comment multiline':r"(\\/*)|(\*\/)",
                'comment multiline with Special MYSQL command': r"\/\*! *\d+",
                'always true ans such conditions': r"(\"|')(( *\))|) ((or)|(OR)) ((\d+(=|>|<|!=|<>)\d+)|([a-zA-Z]+=[a-zA-Z]+))(( )|)(((--)|(\/\*)|(#))|)",
                }
            
            def combinationCount(regexPattern,requestString):
                return len(re.findall(regexPattern, requestString))
            
            for a in combinationRegex:
                df[a] = df.apply (lambda row: combinationCount(combinationRegex[a],row['Sentence']), axis=1)
            return df
        
        ##############################Symbol count##########################
        def numOfSymbols(df):
            symbols=['~','`','!','@','#','$','%','^','&','*','(',')','-','_','+','=','{','}','[',']','|','\\','/',':',';','"',"'",'<','>',',','❡','?']
            
            def countSymbols(symbol,requestString):
                requestString = " " + requestString + " "
                requestString = requestString.lower()
                return  requestString.count(symbol)
            
            for symbol in symbols:
                df[symbol] = df.apply (lambda row: countSymbols(symbol,row['Sentence']), axis=1)
            return df
        
        #calculate length
        df['requestLength'] = df['Sentence'].str.split(" ").str.join("").str.len()
        df.dropna(inplace=True) 
        #count keywords
        df = numOfSqliKeywords(df)
        #count Unusual combos
        df = numberOfUnusualStringCombinations(df)
        #number of Symbols
        df = numOfSymbols(df)
        return df
