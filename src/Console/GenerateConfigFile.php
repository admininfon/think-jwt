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
        $key = Str::random(64);
        $paths = explode('vendor/kangst', __DIR__);
        $root_path = current($paths);
        $think_conf_jwt = $root_path . 'config/jwt.php';
        $init_conf = $root_path . 'vendor/kangst/think-jwt/config/jwt.php';

        // 文件创建
        if (!file_exists($think_conf_jwt)) {
            file_put_contents($think_conf_jwt, str_replace(
                    "'secret' => env('JWT_SECRET', null),",
                    "'secret' => env('JWT_SECRET', " . "'{$key}'" . "),",
                    file_get_contents($init_conf)
                )
            );
            $output->info('配置文件创建成功~');
        }

        // 生成新的secret不会自动替换
        if (file_exists($think_conf_jwt)) {
            $output->info('生成新 secret ：' . PHP_EOL . $key . PHP_EOL . '请替换“jwt.php”文件内“secret”项');
        }
    }
}
