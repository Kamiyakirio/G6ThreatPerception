var lastAiData = null;
var lastAiUrl = null;
var returnData=null;

window.addEventListener('message', function (event) {
    if (event.data === '__REGENERATE__') {
        if (typeof ai === 'function' && typeof lastAiData !== 'undefined' && typeof lastAiUrl !== 'undefined') {
            ai(lastAiData, lastAiUrl,1);
        } else {
            console.error("ai 函数或参数未定义，无法重新生成");
        }
    }
    // console.log(event.data);
});

var ai = function (data, url, force=0) {
    lastAiData = data;
    lastAiUrl = url;
    data.force=force;
    var msgIndex=layer.msg("正在将请求发送至大模型，请勿关闭页面！");
    var loadIndex = layer.load(1);
    var aiResultLayerIndex = 999999;
    $.ajax({
        url: url,
        method: "post",
        headers: {
            'Authorization': localStorage.getItem('token')
        },
        contentType: "application/json",
        dataType: "json",
        data: JSON.stringify(data),
        success: function (response) {
            if(response.code<1000)
            {
                layer.close(loadIndex);
                layer.close(msgIndex);
                layer.closeAll('iFrame');
                layer.open({
                    type: 2,
                    maxmin: true,
                    area: ['60%', '60%'],
                    content: '/page/ai/aiResultTmpl2',
                    success: function (layero, index) {
                        var contentWindow = layero.find('iframe')[0].contentWindow;
                        aiResultLayerIndex = index;
                        contentWindow.postMessage({index:aiResultLayerIndex,data:response.msg});
                    },
                    cancel: function (index, layero, that) {
                        // layer.confirm("关闭窗口后将无法再次查看AI检测结果，再次点击将产生二次花费，是否确认关闭？", function (index) {
                        //     layer.close(aiResultLayerIndex);
                        //     layer.close(index);
                        // });
                        // return false;
                        // console.log(returnData);
                    }
                });
            }else{
                layer.msg(res.msg, {icon: 5});
            }
        },
        error: function (xhr, status, error) {
            let responseText = xhr.responseText;
            layer.close(loadIndex);
            try {
                let json = JSON.parse(responseText);
                layer.msg(json.msg || "发生错误", { icon: 5 });
            } catch (e) {
                layer.msg(responseText || "服务器异常", { icon: 5 });
            }
        }
    });
};