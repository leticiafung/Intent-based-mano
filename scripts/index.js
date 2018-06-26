/**
 * Created by leticia on 2018/6/16.
 */
let names = [],
    sfcNum = 0;
   // Objs = [];//obj对象数组
function  InputObj (){
  this.operation = 'create';
  this.init = function (sfcNum){
      this.name = 'sfc'+ sfcNum;
     // sfcNum++;
      this.VNF = [];
      this.constrain = [];
      this.QoS = {};
  }
}
//只能打开一个页面，同时打开多个可能会有问题，传入的对象可能会有问题？？？
//不是网络的拥有者
//intent analyze
InputObj.prototype.addRule = function () {
    let len = this.VNF.length,
        rule = '',
        lastVnf = this.VNF[len - 1];
    if (len > 0) {
        if (this.VNF[len - 1].type === 'IDS_image') {
            let type = $("select[name ='attackType']").val();
            let ip = '';
            if( $('#toIp').val()==='' ||  $('#toIp1').val()===''|| $('#toIp2').val()===''|| ('#toIp3').val() ==='')
                ip = '$HOME_NET';
            else{
                ip = $('#toIp').val() + '.' + $('#toIp1').val() + '.' + $('#toIp2').val() + '.' + $('#toIp3').val() ;
                if($('#maskt').val()!== '')
                    ip = ip + '/' + $('#maskt').val();
            }
            switch (type) {
                case 'syn':
                    rule = 'alert tcp !$HOME_NET any -> '+ ip +' 22 (flags: S; msg:"Possible TCP DoS"; flow: stateless;' +
                        'threshold: type both, track by_src, count 70, seconds 10; sid:10001;rev:1;)';
                    break;
                case 'ping':
                    rule = 'alert icmp any any -> '+ ip + ' any (msg: “NMAP ping sweep Scan “; dsize:0;sid:10000004; rev:1;)';
                    break;
                case 'tcpscan':
                    rule = 'alert tcp any any -> '+ ip + ' 22 (msg: “NMAP TCP Scan”; sid:10000005; rev:2; )';
                    break;
                default:
                    rule = 'alert tcp any any -> '+ ip + ' 22 (msg:”Nmap XMAS Tree Scan”; flags:FPU; sid:1000006; rev:1;)';
                    break;

            }

        }
        else {
            let stype = $("select[name ='serviceType']").val(),
                actionType = $("select[name ='type']").val(),
                fromt = $('#fromt').val(),
                endt = $('#tot').val(),
                weeks = $('#weekStart').val(),
                weeke = $('#weekEnd').val(),
                speed = ' -m limit --limit ' + $('#speed').val() + '/s',
                sourceIp = $('#fromIp').val() + '.' + $('#fromIp1').val() + '.' + $('#fromIp2').val() + '.' + $('#fromIp3').val() + '/' + $('#maskf').val(),
                destIp = $('#toIp').val() + '.' + $('#toIp1').val() + '.' + $('#toIp2').val() + '.' + $('#toIp3').val() + '/' + $('#maskt').val();
            let week = '-m time --weekdays ';

            sourceIp = sourceIp.split('/')[0].split('.').every((item, index, array) => {
                return !((isNaN(Number(item))) || (item === ''));
            }) === true ? '-s ' + sourceIp : '';
            destIp = destIp.split('/')[0].split('.').every((item, index, array) => {
                return !((isNaN(Number(item))) || (item === ''));
            }) === true ? '-d ' + destIp : '';

            rule = 'iptables -A FORWARD ';
            if (stype === 'web') {
                rule += '-p tcp --dport 80 ';
            }
            else if (stype === 'ftp') {
                rule += '-p tcp --dport 21 ';
            }
            else if (stype === 'dns') {
                rule += '-p tcp --dport 22 ';
            }
            else {
                rule += '-p tcp --dport 22 ';
            }
            //week
            for (let i = Number(weeks); i < Number(weeke); i++) {
                week += i + ',';
            }
            week += Number(weeke);
            rule = rule + sourceIp + destIp + week + ' -m time --timestart ' + fromt + ' --timestop ' + endt + speed + ' -j ' + actionType;
            if (!lastVnf.rule) {
                let firstRule = 'DROP';
                if (actionType === 'ALLOW') {
                    firstRule = 'ACCEPT';
                    lastVnf.rule.push('iptables -P FORWARD ' + firstRule + '\n');
                }
            }
        }
        lastVnf.rule.push(rule);
        alert('需求添加成功！');
    }
};
//sfc 设置
InputObj.prototype.addSfcset = function (){
    let cons = {},
        name = new Date();
    cons.name = name.getTime();
    //no check ,check before!
    let former = $('#former').val(),
        later = $('#later').val();
    if(former !=='' && later !== '') {
        if(former !== later) {
            cons.former = 'vnf' + $('#former').val();
            cons.later = 'vnf' + $('#later').val();
            this.constrain.push(cons);
        }
        else
            alert('顺序约束错误！');
    }
    // else{
    //     alert('顺序约束错误！');
    // };
    let qos = {};
    if($('#bandwidth').val() !== '0') {
        qos.Bandwidth = $('#bandwidth').val();
    }
    if($('#delay').val() !== '0'){
        qos.delay = $('#delay').val();
    }
    this.QoS = qos;
};
// InputObj.prototype.count = 0 ;
// InputObj.prototype.getCount = function(){
//     return this.count;
// };
// //attention 原型方法是否存在隐式屏蔽？？ 原型链继承会存在屏蔽！！！！
// InputObj.prototype.addCount = function (){
//     this.count ++ ;
// };

function chooseSize (){
    let size = $("input[name = 'size']:checked").val(),
        flavor = {};
    if(size === 's'){
        flavor.cpu = '1';
        flavor.memory = '1000 ';
        flavor.disk = '10';
    }
    else if(size === 'm' ){
        flavor.cpu = '1';
        flavor.memory = '2000';
        flavor.disk = '15';
    }
    else {
        flavor.cpu = '1';
        flavor.memory = '3000';
        flavor.disk = '20';
    }
    return flavor;
}
//vnf_name
function setName (count){
    return 'vnf'+ count ;
}
//获取类型
function setType(){
    let type = $("select[name = 'type'] option:selected").val();
    if(type === 'REJECT' || type === 'ACCEPT')
        return 'FW_image';
    else
        return 'IDS_image';
}

function ruleCheck(){
    //time check
    let ftime = $('#fromt').val().split(':'),
        etime  = $('#tot').val().split(':');
    let numft = Number(ftime[0] + ftime[1]),
        numet = Number(etime[0] + etime[1]);
    let attckSelect = $("select[name ='attackType']"),
        serviceSelect = $("select[name ='serviceType']");

    if(isNaN(numft) || isNaN(numet)){
        alert('请输入时间');
        return false;
    }
    else if(numft > numet){
        alert ('起始时间不得大于结束时间！');
        redOutline($('#fromt'));
        return false;
    }
    // week check
    else if(Number($('.weekStart').val()) > Number($('.weekEnd').val())){
        redOutline($('.weekStart'));
        alert('week起始时间不得大于结束时间！');
        return false;
    }
    //再次输入时要复原！！！
    else if(attckSelect.val() === 'none' && serviceSelect.val() === 'none'){
        $('.alerterr').css('visibility','visible');
        let redObj = attckSelect.val() === 'none'? serviceSelect :attckSelect;
        redOutline(redObj);
        return false;
    }
    else
        return true;
}

function redOutline(el){
    if(typeof el === 'object'){
        $(el).css('border','solid red');
    }
}
function ruleReset(){
    //let selector = $('.step2:first').children('select'),//不对，first只能是直接元素吗

    let timeInput = $('#normal').find('input'),
        detailIuput =$("#detail").find('input');
  //  $("select[name='attackType']:first").prop('selected','selected');
    $("select[name='attackType']").val('none');
    $("select[name='serviceType']").val('none');
    // for(let i = 0 ; i < selector.length ; i++){
    //     selector[i].option[0].selected = true;
    // }
    timeInput[0].value = '00:00';
    timeInput[1].value = '23:59';
    timeInput[2].value = '1';
    timeInput[3].value = '7';
    timeInput[4].value = '100';
    for(let j = 0 ; j < detailIuput.length -1 ; j++){
        detailIuput[j].value = '';
    }
    detailIuput[4].value = '0';
    detailIuput[9].value = '0';
}
function sfcsetReset(){
    $('#former').val('');
    $('#later').val('');
    $('#bandwidth').val('0');
    $('#delay').val('0');
}

$(window).ready(()=>{
//全局仅有1个Obj对象！！！
    let addCount = 1;
    let obj = new InputObj();
    obj.init(sfcNum);
    sfcNum++;
    names.push(obj.name);
    //later  be used  as tab switch button
    // $('#sfc').click(()=>{
    //     // let obj = new InputObj();
    //     // obj.init(sfcNum);
    //     // Objs.push(obj);
    // });
    $('#addVNF').click(()=>{
        let vnf = {};
            // obj = Objs[Objs.length -1];
        vnf.name = setName(addCount);
        vnf.type = setType();
        vnf.flavor = chooseSize();
        vnf.rule = [];
        addCount ++;
        obj.VNF.push(vnf);
        //console.log(obj.VNF);
        //display next page
        $('.step1').css('display','none');
        $('.step2').css('display','block');
       // console.log('vnftype:'+ vnf.type);
        if(vnf.type === 'FW_image'){
            $('.attack').css('display','none');
            $('.service').css('display','block');
            $('#sourceIP').css('display','block');
        }
        else{
            $('.attack').css('display','block');
            $('.service').css('display','none');
            $('#sourceIP').css('display','none');
        }
        let intent = $("select[name = 'type'] option:selected").text();
        $('.intentType').text(intent);
      //  console.log($('.intentType').text());
    });

    $('#submitbtn').click(()=>{
        // let obj = Objs[Objs.length -1];
        if(obj.VNF[obj.VNF.length -1 ].rule.length === 0)
            alert('请先添加需求！');
        else {
            $('#former').attr({'max': obj.VNF.length, 'min': '1'});
            $('#later').attr({'max': obj.VNF.length, 'min': '1'});
            $('.step2').css('display', 'none');
            $('.step3').css('display', 'block');
        }
    });

    $('#appendbtn').click(()=>{
        // let last = Objs[Objs.length - 1 ];
        if(ruleCheck()){
            obj.addRule();
            ruleReset();
        }
        console.log('dport:'+ $('#dport').val());
    });

    $('#send').click(()=>{
        // let obj = Objs[Objs.length -1];
        console.log(obj);
        obj.addSfcset();
        let data = JSON.stringify(obj,null,4);
        console.log('senddata' + data);
        $.ajax({
            url:'/datajson',
            data: data,
            // dataType:json,
            type:'post',
            success: function(result){
                console.log(data);
                alert(result);
                obj = undefined;
                obj = new InputObj();
                obj.init(sfcNum);
                sfcNum++;
                names.push(obj.name);
                sfcsetReset();
                $('.step1').css('display','block');
                $('.step3').css('display','none');
            }
        })
        //for test
        // obj = undefined;
        // obj = new InputObj();
        // obj.init(sfcNum);
        // sfcNum++;
        // sfcsetReset();
        // $('.step1').css('display','block');
        // $('.step3').css('display','none');
    });
    $('#back1').click(()=>{
        $('.step1').css('display','block');
        $('.step2').css('display','none');
        $('.attack').css('display','block');
        $('.service').css('display','block');
    });
    $('#back2').click(()=>{
        ruleReset();
        $('.step2').css('display','block');
        $('.step3').css('display','none');
    });
    $('select').click((event)=>{
        console.dir(event.target);
        if($(event.target).css('border')==='solid red'){
            $(event.target).css('border','black');
        }
        if( $('.alerterr').css('visibility') ==='visible')
            $('.alerterr').css('visibility','hidden');
    });

    $('#addConstrain').click(()=>{
        let former = $('#former'),
            later = $('#later');
        obj.addSfcset();
        former.val('');
        later.val('');
    })

});

// let a = $("select[name = 'type']").val();
// alert(a);

//TODO conflict alert




