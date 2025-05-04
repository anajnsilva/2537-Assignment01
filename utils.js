const path = require('path');

global.base_dir = __dirname;
global.abs_path = function(path) {
    return path.join(base_dir + path);
}
global.include = function(file) {
    const path = abs_path('/' + file);
    console.log('including: ', path);
    return require(path);
}