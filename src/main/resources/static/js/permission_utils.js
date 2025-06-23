// 监听所有带 data-url 属性的 a 标签
$(document).on('click', 'a[data-url]', function (e) {
    e.preventDefault(); // 阻止默认跳转行为
    var url = $(this).data('url');
    var authCode = $(this).data('auth'); // 权限码

    // 向后端发送权限校验请求
    $.ajax({
        url: '/api/check-permission',  // 改为你的接口地址
        method: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({ permission: authCode }),
        success: function (res) {
            if (res.allowed) {
                // 允许访问，打开新标签页
                layui.index.openTabsPage(url, $(e.target).text().trim());
            } else {
                layer.msg('无权限访问该页面', { icon: 5 });
            }
        },
        error: function () {
            layer.msg('权限验证失败，请稍后再试', { icon: 2 });
        }
    });
});