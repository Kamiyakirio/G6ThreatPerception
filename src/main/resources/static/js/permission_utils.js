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
            layui.index.openTabsPage(url, $(e.target).text().trim());
        },
        error: function () {
            layer.msg('权限验证失败或没有权限！', {icon: 2});
        }
    });
});