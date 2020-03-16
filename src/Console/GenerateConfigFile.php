<?php


namespace Kangst\JWTAuth\Console;


use think\console\Command;
use think\console\Input;
use think\console\input\Option;
use think\console\Output;
use think\Container;
use think\Exception;
use think\helper\Str;

class GenerateConfigFile extends Command
{
    protected function configure()
    {
        $this->setName('jwt:generate_jwt')
            ->addOption('force', null, Option::VALUE_NONE, 'Force refresh secret')
            ->addOption('create', null, Option::VALUE_NONE,
                'The secret was successfully created, please configure it yourself'
            )
            ->setDescription('生成jwt配置文件');
    }

    /**
     * execute
     *
     * @param Input  $input
     * @param Output $output
     * @return int|void|null
     * @throws Exception
     * @auther Kang Shutian <kst157521@163.com>
     * @date 2020-03-15 22:43:03
     */
    protected function execute(Input $input, Output $output)
    {
        $key = Str::random(64);
        // 输出Secret
        if ($input->hasOption('create')) {
            $output->info('Secret: ' . PHP_EOL . $key . PHP_EOL . 'Created successfully');
            return;
        }

        // 获取项目地址
        if (function_exists('app')) {
            $root_path = app()->getRootPath();
        } elseif (class_exists('Container')) {
            $root_path = Container::get('think\App')->getRootPath();
        } else {
            throw new Exception('未能加载thinkPHP扩展包');
        }

        $think_conf_jwt = $root_path . 'config/jwt.php';
        $vender_conf_jwt = $root_path . 'vendor/kangst/think-jwt/config/jwt.php';

        // 文件创建
        if (!file_exists($think_conf_jwt)) {
            file_put_contents($think_conf_jwt, str_replace(
                    "'secret' => env('JWT_SECRET', null),",
                    "'secret' => env('JWT_SECRET', " . "'{$key}'" . "),",
                    file_get_contents($vender_conf_jwt)
                )
            );
            $output->info('配置文件创建成功~');
            return;
        }

        // 生成新的secret不会自动替换
        if (file_exists($think_conf_jwt)) {
            $secret = app()->config->get('jwt.secret');
            // 输出secret
            if ($secret && !$input->hasOption('force')) {
                $output->info('Secret：' . PHP_EOL . $secret);
                return;
            }

            // 自动写入secret
            if (!$secret && !$input->hasOption('force')) {
                file_put_contents($think_conf_jwt, str_replace(
                        "'secret' => env('JWT_SECRET', ". ($secret ? "'{$secret}'" : "null") . "),",
                        "'secret' => env('JWT_SECRET', " . "'{$key}'" . "),",
                        file_get_contents($think_conf_jwt)
                    )
                );
                $output->info('Secret：' . PHP_EOL . $key . PHP_EOL . 'With successfully');
                return;
            }

            // 强制刷新
            if ($input->hasOption('force') && $output->confirm($input, '确认强制更新 Secret？')) {
                file_put_contents($think_conf_jwt, str_replace(
                        "'secret' => env('JWT_SECRET', ". ($secret ? "'{$secret}'" : "null") . "),",
                        "'secret' => env('JWT_SECRET', " . "'{$key}'" . "),",
                        file_get_contents($think_conf_jwt)
                    )
                );
                $output->info('Secret：' . PHP_EOL . $key . PHP_EOL . 'Refreshed successfully');
                return;
            }
        }
    }
}
