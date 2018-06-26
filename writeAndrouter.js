/**
 * Created by leticia on 2018/6/22.
 */
let child = require('child_process'),
    fs = require('fs');

let writable = fs.createWriteStream('./template_sfc.json',{
    flags: 'w',
    defaultEncoding: 'utf8',
    mode: 0o666,
});

let res = null;

writable.on('error', function(err){
    console.log('write error - %s', err.message);
});

writable.on('finish', function(){
    console.log('write finished');
    // let childexc = childExec("python '../SFCorchestrator/deploy.py'");
    // childexc.then(()=>{
    //     console.log('exec suuccess!');
    //     if(!res){
    //     res.writeHead(200,{'Content-Type':'text/plain'});
    //     res.end("execsuccessful");
    //     }
    // },(error)=>{
    //     console.log('exec error!');
    //     process.exit(0);
    // })
    //for test
    // res.writeHead(200,{'Content-Type':'text/plain'});
    // res.end("execsuccessful");
});

function childExec(command){
    return new Promise((resolve,reject)=> {
        child.exec(exeCommand,(error,stdout,stderr)=> {
            if(error) {
                reject(error);
                return ;
            }
            resolve();
        });
    });
}
function getRes(Res){
    res = Res;
}


module.exports.writable = writable;
module.exports.getRes = getRes;

