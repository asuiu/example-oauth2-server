'use strict';

var Zap = {
    event_notification_key_poll: function (bundle) {
        function guid() {
            function s4() {
                return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
            };
            return s4() + s4() + '-' + s4() + '-' + s4() + '-' + s4() + '-' + s4() + s4() + s4();
        }

        var processId = guid();
        var domain = 'https://212.47.247.218';
        var myParams = bundle.auth_fields;
        myParams.processId = processId;
        var patch_request = {
            'method': 'PATCH',
            'url': domain + '/profiles/1234/eventNotifications',
            'params': myParams,
            'headers': {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            'auth': null,
            'data': null
        };
        var patch_response = z.request(patch_request);
        console.log("Response: " + patch_response.toString());
        console.log('Status: ' + patch_response.status_code);
        console.log('Headers: ' + JSON.stringify(patch_response.headers));
        console.log('Content/Body: ' + patch_response.content);
        console.log('Auth_fields: ' + bundle.auth_fields.toString());

        var get_params = bundle.auth_fields;
        get_params.processId = processId;
        get_params.page = 3;
        var get_request = {
            'method': 'GET',
            'url': domain + '/profiles/1234/eventNotifications',
            'params': get_params,
            'headers': {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            'auth': null,
            'data': null
        };
        var get_response = z.request(get_request);
        console.log('Status: ' + get_response.status_code);
        console.log('Headers: ' + JSON.stringify(get_response.headers));
        console.log('Content/Body: ' + get_response.content);

        var delete_params = bundle.auth_fields;
        delete_params.processId = processId;
        var delete_request = {
            'method': 'DELETE',
            'url': domain + '/profiles/1234/eventNotifications',
            'params': delete_params,
            'headers': {
                'Content-Type': 'application/json',
                'Accept': 'application/json'
            },
            'auth': null,
            'data': null
        };
        var delete_response = z.request(delete_request);
        console.log('Status: ' + delete_response.status_code);
        console.log('Headers: ' + JSON.stringify(delete_response.headers));
        console.log('Content/Body: ' + delete_response.content);

        return JSON.parse(get_response.content);
    }
};