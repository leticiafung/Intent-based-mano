/**
 * Created by leticia on 2018/6/21.
 */
let http = require('http'),
    wr = require('./writeAndrouter'),
    express = require('express');

let app = express();
app.use(express.static(__dirname));
http.createServer(app).listen(9999,'127.0.0.1');
console.log('服务器在9999上运行');

app.route('/datajson')
    .post((req,res)=> {
        console.log('返回');
        let chunks = [];
        let size = 0;
        req.on('data', (chunk) => {
            // chunks.push(chunk);
            // size += chunk.length;
            wr.writable.write(chunk ,'utf8');
        });//receive data
        req.on('end', () => {
            // console.log('chunks:'+ chunks);
            // let content = Buffer.concat(chunks, size).toString();
            // console.log('content'+ content);
            // wr.getRes(res);
            // wr.writable.write(content,'utf8');
            wr.writable.end();
            //需要获取当前的response 对象，使用传参函数
            wr.getRes(undefined);
            res.writeHead(200,{'Content-Type':'text/plain'});
            res.end("execsuccessful");
        });
    });

