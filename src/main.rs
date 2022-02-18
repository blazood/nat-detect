use simple_logger::SimpleLogger;
use nat_detect::nat_detect_with_servers;
use clap::Parser;
use log::LevelFilter;
use rand::Rng;

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {

    #[clap(short, long,help="default use https://github.com/pradt2/always-online-stun")]
    stun_servers: Option<Vec<String>>,

    #[clap(short='c', long, default_value="20")]
    stun_servers_count: usize,

    #[clap(short='v', long="verbose")]
    verbose: bool,

}

#[tokio::main]
pub async fn main(){
    let args: Args = Args::parse();
    let mut logger = SimpleLogger::new();
    if args.verbose {
        logger = logger.with_level(LevelFilter::Debug);
    } else {
        logger = logger.with_level(LevelFilter::Info);
    }
    logger.init().unwrap();
    let vec = args.stun_servers.unwrap_or_else(|| {
        let vec: Vec<String> = include_str!("valid_ipv4s.txt").lines().map(|e|e.trim().to_string()).collect();
        // select 10 server randomly
        let mut rng = rand::thread_rng();
        let mut new_vec = Vec::new();
        for _ in 0..args.stun_servers_count {
            let stun_server = vec[rng.gen_range(0..vec.len())].to_string();
            new_vec.push(stun_server);
        }
        new_vec
    });
    let stun_servers = vec.iter().map(|e| e.as_str()).collect::<Vec<&str>>();


    match nat_detect_with_servers(stun_servers.as_slice()).await {
        Ok(r) => {
            println!("{}","#".repeat(32));
            println!("   nat_type: {:?}", r.0);
            println!("public_addr: {}", r.1);
        }
        Err(_) => {
            println!("can not detect!");
        }
    }

}
