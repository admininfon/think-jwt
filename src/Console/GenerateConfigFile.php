<?php


namespace Kangst\JWTAuth\Console;


use think\console\Command;
use think\console\Input;
use think\console\Output;
use think\helper\Str;

class GenerateConfigFile extends Command
{
    protected function configure()
    {
        $this->setName('jwt:generate_jwt')->setDescription('生成jwt配置文件');
    }

    protected function execute(Input $input, Output $output)
    {
        $paths = explode('vendor/kangst', __DIR__);
        $root_path = current($paths);
        $think_conf_jwt = $root_path . 'config/jwt.php';
        if (!file_exists($think_conf_jwt)) {
            $init_conf = $root_path  . 'vendor/kangst/think-jwt/config/jwt.php';
            file_put_contents($think_conf_jwt, file_get_contents($init_conf));
        }

        $key = Str::random(32);
        $output->info('成功创建 secret ：' . PHP_EOL . $key . PHP_EOL . '请复制添加进【jwt.php】配置文件');
    }
}
