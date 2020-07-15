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


@bp.route('/')
@login_required
def index():
    db = get_db()
    profiles = db.execute(
        'SELECT * from wafrules'
    ).fetchall()
    return render_template('index.html', curprof=get_curprof() ,profiles=profiles)


def get_profile(id):
    profile = (
        get_db()
        .execute(
            "SELECT * FROM wafrules where profID = ?",
            (id,),
        )
        .fetchone()
    )

    if profile is None:
        abort(404, f"Profile id {id} doesn't exist.")

    return profile

def get_ipclients(id):
    ipclients = (
        get_db()
        .execute(
            "SELECT * FROM ipclients where profID = ?",
            (id,),
        )
        .fetchall()
    )
    if ipclients is None:
        ipclients=[]

    return ipclients

def get_countryrule(id):
    country = (
        get_db()
        .execute(
            "SELECT * FROM countryrule where profID = ?",
            (id,),
        )
        .fetchall()
    )
    if country is None:
        country=[]

    return country

def get_curprof():
    curprof=get_db().execute("SELECT profID FROM CURPROF").fetchone()
    return curprof['profID']

@bp.route("/create", methods=("GET", "POST"))
@login_required
def create():
    if request.method == "POST":
        error=None
        try:title = request.form["title"]
        except:error="Title is required!"

        try:description = request.form["description"]
        except:description=None 

        try:onlyallowedip = request.form["onlyallowedip"]
        except:onlyallowedip = None

        try:onlyallowedcountries = request.form["onlyallowedcountries"]
        except:onlyallowedcountries = None

        try:proxyblock = request.form["proxyblock"]
        except:proxyblock = None

        try:intelligenttest = request.form["intelligenttest"]
        except:intelligenttest = None

        try:maxrcv = request.form["maxrcv"]
        except:maxrcv = None

        try:requesthold = request.form["requesthold"]
        except:requesthold = None

        try:intelligentmode = request.form["intelligentmode"]
        except:intelligentmode = None

        db = get_db()
        parms=""
        l=tuple()
        if description!=None:
            l+=(description,)
            parms+=" description,"

        if title!=None:
            l+=(title,)
            parms+=" title,"
        
        if onlyallowedip!=None:
            l+=(onlyallowedip,)
            parms+=" onlyallowedip,"

        if onlyallowedcountries!=None:
            l+=(onlyallowedcountries,)
            parms+=" onlyallowedcountries,"

        if proxyblock!=None:
            l+=(proxyblock,)
            parms+=" proxyblock,"

        if intelligenttest!=None:
            l+=(intelligenttest,)
            parms+=" intelligenttest,"

        if maxrcv!=None:
            l+=(maxrcv,)
            parms+=" maxrcv,"

        if requesthold!=None:
            l+=(requesthold,)
            parms+=" requesthold,"

        if intelligentmode!=None:
            l+=(intelligentmode,)
            parms+=" intelligentmode"
        ques=""
        for i in range(0,len(l)):
            if i!=len(l)-1:ques+=" '"+l[i]+"',"
            else:ques+=" '"+l[i]+"'"
        
        if error is not None:
            flash(error)
        else:
            db = get_db()
            q="INSERT INTO wafrules ("+parms+") VALUES ("+ques+")"
            print(q)
            db.execute(q)
            db.commit()
            return redirect(url_for("dashboard.index"))

    return render_template("create.html")


@bp.route("/<int:id>/update", methods=("GET", "POST"))
@login_required
def update(id):
    profile = get_profile(id)
    ipclients = get_ipclients(id)
    countryrules = get_countryrule(id)
    if request.method == "POST":

        try:title = request.form["title"]
        except:title=None

        try:description = request.form["description"]
        except:description=None 

        try:onlyallowedip = request.form["onlyallowedip"]
        except:onlyallowedip = None

        try:onlyallowedcountries = request.form["onlyallowedcountries"]
        except:onlyallowedcountries = None

        try:proxyblock = request.form["proxyblock"]
        except:proxyblock = None

        try:intelligenttest = request.form["intelligenttest"]
        except:intelligenttest = None

        try:maxrcv = request.form["maxrcv"]
        except:maxrcv = None

        try:requesthold = request.form["requesthold"]
        except:requesthold = None

        try:intelligentmode = request.form["intelligentmode"]
        except:intelligentmode = None

        try:ipclientUpdate = json.loads(request.form["ipclientUpdate"])
        except:ipclientUpdate=None

        try:ipclientAdd = json.loads(request.form["ipclientAdd"])
        except:ipclientAdd=None

        try:ipclientDel = json.loads(request.form["ipclientDel"])
        except:ipclientDel=None

        try:countryruleUpdate = json.loads(request.form["countryruleUpdate"])
        except:countryruleUpdate=None

        try:countryruleAdd = json.loads(request.form["countryruleAdd"])
        except:countryruleAdd=None

        try:countryruleDel = json.loads(request.form["countryruleDel"])
        except:countryruleDel=None
        print(countryruleAdd)
        
        ##################################IP client##################
        ##Updating IPclients
        db = get_db()
        if ipclientUpdate!=None:
            if len(ipclientUpdate)>0:
                for i in ipclientUpdate:
                    ip=None
                    status=None
                    cid=i.split("*")[1]
                    for j in ipclientUpdate[i]:
                        try:
                            if j=="ip":ip=ipclientUpdate[i][j]
                            elif j=="status":status=int(ipclientUpdate[i][j])
                        except:
                            ip=None
                            pass
                    if ip!=None:
                        try:
                            qry="UPDATE ipclients SET ip='"+ip+"', status="+str(status)+" WHERE id = "+str(cid)
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass

        ##Adding Ipclients
        db = get_db()
        if ipclientAdd!=None:
            if len(ipclientAdd)>0:
                for i in ipclientAdd:
                    ip=None
                    status=None
                    for j in ipclientAdd[i]:
                        try:
                            if j=="ip":ip=ipclientAdd[i][j]
                            elif j=="status":status=int(ipclientAdd[i][j])
                        except:
                            ip=None
                            pass
                    if ip!=None:
                        try:
                            qry="INSERT INTO ipclients (ip,status,profID) VALUES ('"+ip+"',"+str(status)+","+str(id)+")"
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass

        ##Deleting IPclients
        db = get_db()
        if ipclientDel!=None:
            if len(ipclientDel)>0:
                for i in ipclientDel:
                    cid=None
                    try:cid=i.split("*")[1]
                    except:cid=None
                    if cid!=None:
                        try:
                            qry="DELETE FROM ipclients WHERE id="+str(cid)+" AND profID="+str(id)
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass

        ##################################Country Rule##################
        ##Updating countryrule
        db = get_db()
        if countryruleUpdate!=None:
            if len(countryruleUpdate)>0:
                for i in countryruleUpdate:
                    country=None
                    countryCode=None
                    status=None
                    cid=i.split("*")[1]
                    for j in countryruleUpdate[i]:
                        try:
                            if j=="country":
                                country=countryruleUpdate[i][j][:-3]
                                countryCode=countryruleUpdate[i][j][-2:]
                            elif j=="status":status=int(countryruleUpdate[i][j])
                        except:
                            country=None
                            countryCode=None
                            pass
                    if country!=None:
                        try:
                            qry="UPDATE countryrule SET country='"+country+"', countryCode='"+countryCode+"', status="+str(status)+" WHERE id = "+str(cid)
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass

        ##Adding countryrule
        db = get_db()
        if countryruleAdd!=None:
            if len(countryruleAdd)>0:
                for i in countryruleAdd:
                    country=None
                    countryCode=None
                    status=None
                    for j in countryruleAdd[i]:
                        try:
                            if j=="country":
                                country=countryruleAdd[i][j][:-3]
                                countryCode=countryruleAdd[i][j][-2:]
                            elif j=="status":status=int(countryruleAdd[i][j])
                        except:
                            country=None
                            countryCode=None
                            pass
                    if country!=None:
                        try:
                            qry="INSERT INTO countryrule (country,countryCode,status,profID) VALUES ('"+country+"','"+countryCode+"',"+str(status)+","+str(id)+")"
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass

        ##Deleting countryrule
        db = get_db()
        if countryruleDel!=None:
            if len(countryruleDel)>0:
                for i in countryruleDel:
                    cid=None
                    try:cid=i.split("*")[1]
                    except:cid=None
                    if cid!=None:
                        try:
                            qry="DELETE FROM countryrule WHERE id="+str(cid)+" AND profID="+str(id)
                            db.execute(qry)
                            db.commit()
                        except:
                            traceback.print_exc()
                            pass



        #updating Wafrules
        db = get_db()
        parms=""
        l=tuple()
        if description!=None:
            l+=(description,)
            parms+=" description = ?,"

        if title!=None:
            l+=(title,)
            parms+=" title = ?,"
        
        if onlyallowedip!=None:
            l+=(int(onlyallowedip),)
            parms+=" onlyallowedip = ?,"

        if onlyallowedcountries!=None:
            l+=(int(onlyallowedcountries),)
            parms+=" onlyallowedcountries = ?,"

        if proxyblock!=None:
            l+=(int(proxyblock),)
            parms+=" proxyblock = ?,"

        if intelligenttest!=None:
            l+=(int(intelligenttest),)
            parms+=" intelligenttest = ?,"

        if maxrcv!=None:
            l+=(int(maxrcv),)
            parms+=" maxrcv = ?,"

        if requesthold!=None:
            l+=(int(requesthold),)
            parms+=" requesthold = ?,"

        if intelligentmode!=None:
            l+=(intelligentmode,)
            parms+=" intelligentmode = ?"
        l+=(id,)
        if len(l)>1:
            try:
                db.execute("UPDATE wafrules SET "+parms+" WHERE profID = ?", l)
                db.commit()
            except:
                traceback.print_exc()
                pass
        return redirect(url_for("dashboard.index"))
    else:
        return render_template("update.html", profile=profile,ipclients=ipclients,countryrules=countryrules)


@bp.route("/setcurprof", methods=("POST",))
@login_required
def setcurprof():
    db = get_db()
    profID=request.form['curprof']
    qr="UPDATE CURPROF SET profID="+str(profID)+" WHERE profID ="+str(get_curprof())
    print("#############################################",qr)
    db.execute(qr)
    db.commit()
    return redirect(url_for("dashboard.index"))


@bp.route("/<int:id>/delete", methods=("POST",))
@login_required
def delete(id):
    get_profile(id)
    db = get_db()
    db.execute("DELETE FROM wafrules WHERE profID = ?", (id,))
    db.commit()
    return redirect(url_for("dashboard.index"))