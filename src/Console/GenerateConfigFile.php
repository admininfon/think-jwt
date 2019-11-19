<?php


namespace Kangst\JWTAuth\Console;


use think\App;
use think\Config;
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
        $config = new Config();
        $think_app = new App();

        $config_path = $think_app->getConfigPath();
        $think_conf_jwt = $config_path . 'jwt.php';
        $output->writeln($think_conf_jwt);

        if (!file_exists($think_conf_jwt)) {
            $vendor_path = $think_app->env->get('vendor_path');
            $output->writeln($vendor_path);
            $output->writeln(__DIR__);

            $init_conf = $vendor_path  . 'kangst/think-jwt/config/jwt.php';
            file_put_contents($think_conf_jwt, file_get_contents($init_conf));
        }

        if (!$config->has('jwt.secret')) {
            $key = Str::random(32);
            $output->info('成功创建 secret ：' . PHP_EOL . $key . PHP_EOL . '请复制添加进【jwt.php】配置文件');
        }
    }
}
