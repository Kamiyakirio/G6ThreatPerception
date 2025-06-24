// 监听所有带 data-url 属性的 a 标签
$(document).on('click', 'a[data-url]', function (e) {
    e.preventDefault(); // 阻止默认跳转行为
    var url = $(this).data('url');
    var authCode = $(this).data('auth'); // 权限码

    // 向后端发送权限校验请求
    $.ajax({
        url: '/check_permission/' + authCode,  // 改为你的接口地址
        method: 'GET',
        headers: {
            'Authorization': localStorage.getItem('token')
        },
        success: function (res) {
            // 允许访问，打开新标签页
            // 始终调用 openTabsPage：如果标签页已存在，则自动激活；如果不存在，则新建
            layui.index.openTabsPage(url, $(e.target).text().trim());

            // 延迟一点时间再刷新 iframe，确保 iframe 已加载并处于当前活动状态
            setTimeout(function () {
                var iframe = $('#LAY_app_body > div.layadmin-tabsbody-item.layui-show > iframe');
                if (iframe.length > 0) {
                    iframe[0].contentWindow.location.reload();
                }
            }, 30);
        },
        error: function () {
            layer.msg('权限验证失败或没有权限！', {icon: 2});
        }
    });
});