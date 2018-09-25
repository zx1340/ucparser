import frida
from hook import *
from flask import * 
from wtforms import *
app = Flask(__name__)


trace_data = []

def get_data():
    block = []
    with open('trace.log','r') as f:
        data = f.read().split('\n')
    print len(data)
    start = True
    for line in data:
        if len(line)==0:
            break
        if line[0]=='\t':
            if start:
                x={'id':len(block)}
                x['reg']=[line]
                start=False
            else:
                x['reg'].append(line)
        else:
            x['asm']=line
            block.append(x)
            start=True

    return block
def check(blocks,query,qtype):
    ret=[]
    if qtype=='q':
        for block in blocks:
            for reg in block['reg']:
                if query in reg:
                    ret.append(block)

    elif qtype=='pc':
        for block in blocks:
            if query in block['asm']:
                ret.append(block)
    
    elif qtype=='ft':
        print("CHECK FROM %s to %s"%(query[0],query[1]))
        start=False
        for block in blocks:
            if start:
                ret.append(block)
            if query[0].lower() in block['asm']:
                print(block)
                ret.append(block)
                start=True
            if query[1].lower() in block['asm']:
                print("END"+str(block))
                break
    return ret
        


class ReusableForm(Form):
    name = TextField('Name:', validators=[validators.required()])
 
@app.route("/",methods=['GET'])
def index(): 
    user = {'username': 'zx'}
    posts = get_data()
    qposts=[]
    if request.method=='GET':
        query = request.args.get('q',default="LOL",type=str)
        pc = request.args.get('pc',default="LOL",type=str)
        f = request.args.get('f',default="0xffffffff",type=str)
        t = request.args.get('t',default="0xffffffff",type=str)
        if query:
            qposts += check(posts,query,"q")
        if pc:
            qposts += check(posts,pc,"pc")
        if f and t:
            qposts += check(posts,[f,t],"ft")


    return render_template('index.html', title='Home',form=form, user=user, posts=qposts)

@app.route("/hello")
def hello():  
	return "Hello World!"

@app.route("/hello/<string:name>/")
def hello_user(name):  
	return "Hello, %s" % name

if __name__ == "__main__":  
	app.run(debug=True)
