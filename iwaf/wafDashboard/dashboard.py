from flask import Blueprint
from flask import flash
from flask import g
from flask import redirect
from flask import render_template
from flask import request
from flask import url_for
from werkzeug.exceptions import abort

from .auth import login_required
from .db import get_db
import json
import traceback

bp = Blueprint("dashboard", __name__)

def getCurrentServer():
    currentServer = get_db().execute("SELECT host,port FROM CURRENT_SERVER").fetchone()
    return currentServer

@bp.route('/')
@login_required
def index():
    db = get_db()
    profiles = db.execute(
        'SELECT * from WAF_RULES'
    ).fetchall()
    return render_template('index.html', currentServer = getCurrentServer(), currentProfile = getCurrentProfile() ,profiles = profiles)


def getProfile(id):
    profile = (
        get_db()
        .execute(
            "SELECT * FROM WAF_RULES where profID = ?",
            (id,),
        )
        .fetchone()
    )

    if profile is None:
        abort(404, f"Profile id {id} doesn't exist.")
    return profile

def getIpClients(id):
    ipClients = (
        get_db()
        .execute(
            "SELECT * FROM ipClients where profID = ?",
            (id,),
        )
        .fetchall()
    )
    if ipClients is None:
        ipClients = []
    return ipClients

def getCountryRule(id):
    country = (
        get_db()
        .execute(
            "SELECT * FROM COUNTRY_RULE where profID = ?",
            (id,),
        )
        .fetchall()
    )
    if country is None:
        country = []

    return country

def getCurrentProfile():
    currentProfile = get_db().execute("SELECT profID FROM CURRENT_PROFILE").fetchone()
    return currentProfile['profID']

@bp.route("/create", methods =("GET", "POST"))
@login_required
def create():
    if request.method == "POST":
        error = None
        try:
            title = request.form["title"]
        except:
            error = "Title is required!"

        try:
            description = request.form["description"]
        except:
            description = None 

        try:
            onlyAllowedIp = request.form["OnlyAllowedIP"]
        except:
            onlyAllowedIp = None

        try:
            onlyAllowedCountries = request.form["onlyAllowedCountries"]
        except:
            onlyAllowedCountries = None

        try:
            proxyBlock = request.form["proxyBlock"]
        except:
            proxyBlock = None

        try:
            intelligentTest = request.form["intelligentTest"]
        except:
            intelligentTest = None

        try:
            maxRcv = request.form["maxRcv"]
        except:
            maxRcv = None

        try:
            requestHold = request.form["requestHold"]
        except:
            requestHold = None

        try:
            intelligentMode = request.form["intelligentMode"]
        except:
            intelligentMode = None

        db = get_db()
        parameters = ""
        parameterValues = tuple()
        if description != None:
            parameterValues += (description,)
            parameters += " description,"

        if title!= None:
            parameterValues += (title,)
            parameters += " title,"
        
        if onlyAllowedIp != None:
            parameterValues += (onlyAllowedIp,)
            parameters += " OnlyAllowedIP,"

        if onlyAllowedCountries != None:
            parameterValues += (onlyAllowedCountries,)
            parameters += " onlyAllowedCountries,"

        if proxyBlock != None:
            parameterValues += (proxyBlock,)
            parameters += " proxyBlock,"

        if intelligentTest != None:
            parameterValues += (intelligentTest,)
            parameters += " intelligentTest,"

        if maxRcv != None:
            parameterValues += (maxRcv,)
            parameters += " maxRcv,"

        if requestHold != None:
            parameterValues += (requestHold,)
            parameters += " requestHold,"

        if intelligentMode != None:
            parameterValues += (intelligentMode,)
            parameters += " intelligentMode"
        ques = ""
        for i in range(0,len(parameterValues)):
            if i != len(parameterValues) - 1:
                ques += " '" + parameterValues[i] + "',"
            else:
                ques += " '" + parameterValues[i] + "'"
        
        if error is not None:
            flash(error)
        else:
            db = get_db()
            qr = "INSERT INTO WAF_RULES (" + parameters + ") VALUES (" + ques + ")"
            print(qr)
            db.execute(qr)
            db.commit()
            return redirect(url_for("dashboard.index"))

    return render_template("create.html")

@bp.route("/<int:id>/update", methods =("GET", "POST"))
@login_required
def update(id):
    profile = getProfile(id)
    ipClients = getIpClients(id)
    countryRules = getCountryRule(id)
    if request.method == "POST":

        try:
            title = request.form["title"]
        except:
            title= None

        try:
            description = request.form["description"]
        except:
            description = None 

        try:
            onlyAllowedIp = request.form["OnlyAllowedIP"]
        except:
            onlyAllowedIp = None

        try:
            onlyAllowedCountries = request.form["onlyAllowedCountries"]
        except:
            onlyAllowedCountries = None

        try:
            proxyBlock = request.form["proxyBlock"]
        except:
            proxyBlock = None

        try:
            intelligentTest = request.form["intelligentTest"]
        except:
            intelligentTest = None

        try:
            maxRcv = request.form["maxRcv"]
        except:
            maxRcv = None

        try:
            requestHold = request.form["requestHold"]
        except:
            requestHold = None

        try:
            intelligentMode = request.form["intelligentMode"]
        except:
            intelligentMode = None

        try:
            ipClientUpdate = json.loads(request.form["ipClientUpdate"])
        except:
            ipClientUpdate= None

        try:
            ipClientAdd = json.loads(request.form["ipClientAdd"])
        except:
            ipClientAdd= None

        try:
            ipClientDel = json.loads(request.form["ipClientDel"])
        except:
            ipClientDel= None

        try:
            countryRuleUpdate = json.loads(request.form["countryRuleUpdate"])
        except:
            countryRuleUpdate= None

        try:
            countryRuleAdd = json.loads(request.form["countryRuleAdd"])
        except:
            countryRuleAdd= None

        try:
            countryRuleDel = json.loads(request.form["countryRuleDel"])
        except:
            countryRuleDel= None
        print(countryRuleAdd)
        
        ##################################IP client##################
        ##Updating ipClients
        db = get_db()
        if ipClientUpdate != None:
            if len(ipClientUpdate) > 0:
                for i in ipClientUpdate:
                    ip = None
                    status = None
                    id = i.split("*")[1]
                    for j in ipClientUpdate[i]:
                        try:
                            if j == "ip":
                                ip = ipClientUpdate[i][j]
                            elif j == "status":
                                status = int(ipClientUpdate[i][j])
                        except:
                            ip = None
                            pass
                    if ip != None:
                        try:
                            qry = "UPDATE ipClients SET ip='" + ip + "', status = " + str(status) + " WHERE id = " + str(id)
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass

        ##Adding ipClients
        db = get_db()
        if ipClientAdd != None:
            if len(ipClientAdd)>0:
                for i in ipClientAdd:
                    ip = None
                    status = None
                    for j in ipClientAdd[i]:
                        try:
                            if j == "ip":
                                ip= ipClientAdd[i][j]
                            elif j == "status":
                                status = int(ipClientAdd[i][j])
                        except:
                            ip = None
                            pass
                    if ip != None:
                        try:
                            qry = "INSERT INTO ipClients (ip,status,profID) VALUES ('" + ip + "'," + str(status) + "," + str(id) + ")"
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass

        ##Deleting ipClients
        db = get_db()
        if ipClientDel != None:
            if len(ipClientDel) > 0:
                for i in ipClientDel:
                    id = None
                    try:
                        id = i.split("*")[1]
                    except:
                        id = None
                    if id != None:
                        try:
                            qry = "DELETE FROM ipClients WHERE id= " + str(id) + " AND profID= " + str(id)
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass

        ##################################Country Rule##################
        ##Updating COUNTRY_RULE
        db = get_db()
        if countryRuleUpdate != None:
            if len(countryRuleUpdate) >0:
                for i in countryRuleUpdate:
                    country = None
                    countryCode = None
                    status = None
                    id = i.split("*")[1]
                    for j in countryRuleUpdate[i]:
                        try:
                            if j == "country":
                                country =countryRuleUpdate[i][j][:-3]
                                countryCode =countryRuleUpdate[i][j][-2:]
                            elif j == "status":
                                status = int(countryRuleUpdate[i][j])
                        except:
                            country = None
                            countryCode = None
                            pass
                    if country != None:
                        try:
                            qry = "UPDATE COUNTRY_RULE SET country='" + country + "', countryCode='" + countryCode + "', status = " + str(status) + " WHERE id = " + str(id)
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass

        ##Adding COUNTRY_RULE
        db = get_db()
        if countryRuleAdd != None:
            if len(countryRuleAdd) >0:
                for i in countryRuleAdd:
                    country = None
                    countryCode = None
                    status = None
                    for j in countryRuleAdd[i]:
                        try:
                            if j == "country":
                                country = countryRuleAdd[i][j][:-3]
                                countryCode = countryRuleAdd[i][j][-2:]
                            elif j == "status":
                                status = int(countryRuleAdd[i][j])
                        except:
                            country = None
                            countryCode = None
                            pass
                    if country != None:
                        try:
                            qry = "INSERT INTO COUNTRY_RULE (country,countryCode,status,profID) VALUES ('" + country + "','" + countryCode + "'," + str(status) + "," + str(id) + ")"
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass

        ##Deleting COUNTRY_RULE
        db = get_db()
        if countryRuleDel != None:
            if len(countryRuleDel) >0:
                for i in countryRuleDel:
                    id = None
                    try:
                        id = i.split("*")[1]
                    except:
                        id = None
                    if id != None:
                        try:
                            qry = "DELETE FROM COUNTRY_RULE WHERE id= " + str(id) + " AND profID= " + str(id)
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass

        # updating Waf rules
        db = get_db()
        parameters = ""
        parameterValues = tuple()
        if description != None:
            parameterValues += (description,)
            parameters += " description = ?,"

        if title != None:
            parameterValues += (title,)
            parameters += " title = ?,"
        
        if onlyAllowedIp != None:
            parameterValues += (int(onlyAllowedIp),)
            parameters += " OnlyAllowedIP = ?,"

        if onlyAllowedCountries != None:
            parameterValues += (int(onlyAllowedCountries),)
            parameters += " onlyAllowedCountries = ?,"

        if proxyBlock != None:
            parameterValues += (int(proxyBlock),)
            parameters += " proxyBlock = ?,"

        if intelligentTest != None:
            parameterValues += (int(intelligentTest),)
            parameters += " intelligentTest = ?,"

        if maxRcv != None:
            parameterValues += (int(maxRcv),)
            parameters += " maxRcv = ?,"

        if requestHold != None:
            parameterValues += (int(requestHold),)
            parameters += " requestHold = ?,"

        if intelligentMode != None:
            parameterValues += (intelligentMode,)
            parameters += " intelligentMode = ?"
        parameterValues += (id,)
        if len(parameterValues) >1:
            try:
                db.execute("UPDATE WAF_RULES SET " + parameters + " WHERE profID = ?", parameterValues)
                db.commit()
            except:
                traceback.print_exc()
                pass
        return redirect(url_for("dashboard.index"))
    else:
        return render_template("update.html", profile=profile, ipClients = ipClients, countryRules =countryRules)

@bp.route("/setCurrentProfile", methods =("POST",))
@login_required
def setCurrentProfile():
    db = get_db()
    profID = request.form['currentProfile']
    qr = "UPDATE CURRENT_PROFILE SET profID= " + str(profID) + " WHERE profID = " + str(getCurrentProfile())
    print("#############################################",qr)
    db.execute(qr)
    db.commit()
    return redirect(url_for("dashboard.index"))

@bp.route("/setCurrentServer", methods =("POST",))
@login_required
def setCurrentServer():
    db = get_db()
    host = request.form['currentServerHost']
    port = request.form['currentServerPort']
    qr = "UPDATE CURRENT_SERVER SET host='" + str(host) + "' , port= " + str(port)
    print("#############################################",qr)
    db.execute(qr)
    db.commit()
    return redirect(url_for("dashboard.index"))

@bp.route("/<int:id>/delete", methods =("POST",))
@login_required
def delete(id):
    getProfile(id)
    db = get_db()
    db.execute("DELETE FROM WAF_RULES WHERE profID = ?", (id,))
    db.commit()
    return redirect(url_for("dashboard.index"))