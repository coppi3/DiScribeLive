//! Requires the "client", "standard_framework", and "voice" features be enabled
//! in your Cargo.toml, like so:
//!
//! ```toml
//! [dependencies.serenity]
//! git = "https://github.com/serenity-rs/serenity.git"
//! features = ["client", "standard_framework", "voice"]
//! ```
use serenity::client::Client as SerenityClient;
use serenity::client::ClientBuilder;
use serenity::model::prelude::Member;
// use serenity::model::prelude::UserId;
use serenity::{
    async_trait,
    client::{Context, EventHandler},
    framework::{
        standard::{
            macros::{command, group},
            Args, CommandResult,
        },
        StandardFramework,
    },
    // http::CacheHttp,
    model::{channel::Message, gateway::Ready, id::ChannelId, prelude::GuildId},
    prelude::{GatewayIntents, Mentionable, TypeMapKey},
    Result as SerenityResult,
};
use songbird::{
    driver::DecodeMode,
    model::payload::{ClientDisconnect, Speaking},
    Config, CoreEvent, Event, EventContext, EventHandler as VoiceEventHandler, SerenityInit,
    Songbird,
};
use songbird::{error::JoinError, Config as SongbirdConfig};
use songbird::{
    events::context_data::{SpeakingUpdateData, VoiceData},
    Call,
};
use std::ffi::OsStr;
use std::fmt;
use std::fs::read_to_string;
use std::fs::File;
use std::fs::FileType;
use std::io::BufRead;
use std::io::BufReader;
use std::{
    collections::VecDeque,
    env,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::fs;
use tokio::process::Child;
use tokio::{process::Command, time::sleep};
use tracing_subscriber::{fmt as fmtt, EnvFilter};
struct Handler;

// Helpers
use serenity::client::Cache;
use serenity::http::CacheHttp as SerenityCacheHttp;
use serenity::http::Http;
use serenity::CacheAndHttp;
use std::sync::Arc;

/// Instead of the built-in serenity struct, we use this
#[derive(Clone)]
pub struct CacheHttp {
    pub cache: Arc<Cache>,
    pub http: Arc<Http>,
}

impl SerenityCacheHttp for CacheHttp {
    fn http(&self) -> &Http {
        &self.http
    }
    fn cache(&self) -> Option<&Arc<Cache>> {
        Some(&self.cache)
    }
}

impl From<&Context> for CacheHttp {
    fn from(ctx: &Context) -> Self {
        CacheHttp {
            cache: ctx.cache.clone(),
            http: ctx.http.clone(),
        }
    }
}

impl From<&Arc<CacheAndHttp>> for CacheHttp {
    fn from(cachehttp: &Arc<CacheAndHttp>) -> Self {
        CacheHttp {
            cache: cachehttp.cache.clone(),
            http: cachehttp.http.clone(),
        }
    }
}

impl AsRef<Cache> for CacheHttp {
    fn as_ref(&self) -> &Cache {
        self.cache.as_ref()
    }
}
const SAMPLE_RATE: f64 = 48_000.0;
const CHANNEL_COUNT: u8 = 2;
const RECORDING_LENGTH: u64 = 60;
const RECORDING_FOLDER: &str = "RECS";
fn samples_to_duration(samples: usize) -> Duration {
    Duration::from_nanos((samples as f64 / SAMPLE_RATE / CHANNEL_COUNT as f64 * 1e9).round() as u64)
}
fn nanos_to_samples(nanos: u128) -> usize {
    (nanos as f64 * 1e-9 * SAMPLE_RATE * CHANNEL_COUNT as f64).round() as usize
}
#[derive(Debug)]
pub enum RecordingError {
    IoError(std::io::Error),
    NoData,
}

impl fmt::Display for RecordingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::result::Result<(), std::fmt::Error> {
        match self {
            RecordingError::NoData => write!(f, "RecordingError: no data to record"),
            RecordingError::IoError(err) => write!(f, "RecordingError: IoError occurred. {}", err),
        }
    }
}

impl From<std::io::Error> for RecordingError {
    fn from(err: std::io::Error) -> Self {
        RecordingError::IoError(err)
    }
}
#[async_trait]
impl EventHandler for Handler {
    async fn ready(&self, _: Context, ready: Ready) {
        println!("{} is connected!", ready.user.name);
    }
}
use std::time::SystemTime;
#[derive(Clone)]
struct VoiceSnippet {
    timestamp: SystemTime,
    data: Vec<i16>,
}

impl VoiceSnippet {}
use serenity::model::voice_gateway::id::UserId;
struct UserData {
    user_id: UserId,
    last_voice_activity: SystemTime,
    recordings: VecDeque<VoiceSnippet>,
}
impl UserData {
    pub fn new(user_id: UserId) -> Self {
        Self {
            user_id,
            // very questionable
            last_voice_activity: SystemTime::now(),
            recordings: VecDeque::new(),
        }
    }
}
use serenity::prelude::{Mutex, RwLock};
use std::collections::HashMap;

#[derive(Clone)]
struct Receiver {
    guild_id: GuildId,
    // map u32 SSRC to users
    users: Arc<RwLock<HashMap<u32, Arc<Mutex<UserData>>>>>,
}

impl Receiver {
    pub fn new(guild_id: GuildId) -> Self {
        // You can manage state here, such as a buffer of audio packet bytes so
        // you can later store them in intervals.
        Self {
            guild_id,
            users: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}
impl Receiver {
    // #[instrument(skip(self, cache_and_http), err)]
    //
    // pub async fn save_user_single_recording(&self, cache_and_http: CacheHttp, user_id: UserId) {
    //     let mut recording: VecDeque<VoiceSnippet> = VecDeque::new();
    //     {
    //         let users = self.users.read().await;
    //     }
    // }
    //
    pub async fn mix_recording(
        &self,
        cache_and_http: CacheHttp,
    ) -> Result<Vec<i16>, RecordingError> {
        let mut audio: Vec<i16> = Vec::new();
        let mut recordings: HashMap<UserId, VecDeque<VoiceSnippet>> = HashMap::new();
        {
            let users = self.users.read().await;

            for user in users.values() {
                let user = user.lock().await;

                if !user.recordings.is_empty() {
                    recordings.insert(user.user_id, user.recordings.clone());
                }
            }
        }
        dbg!(recordings.len());

        // We make all files have the same length by padding them at the start
        let first_start_time = recordings
            .iter()
            .filter_map(|(_, recs)| recs.front().map(|first_rec| first_rec.timestamp))
            .min()
            .ok_or(RecordingError::NoData)?;
        let last_end_time = recordings
            .iter()
            .filter_map(|(_, recs)| {
                recs.back()
                    .map(|last_rec| last_rec.timestamp + samples_to_duration(last_rec.data.len()))
            })
            .max()
            .ok_or(RecordingError::NoData)?;
        dbg!(first_start_time, last_end_time);
        Ok(audio)
    }

    pub async fn save_recording(&self, cache_and_http: CacheHttp) -> Result<(), RecordingError> {
        let mut recordings: HashMap<UserId, VecDeque<VoiceSnippet>> = HashMap::new();
        {
            let users = self.users.read().await;

            for user in users.values() {
                let user = user.lock().await;

                if !user.recordings.is_empty() {
                    recordings.insert(user.user_id, user.recordings.clone());
                }
            }
        }
        dbg!(recordings.len());

        // We make all files have the same length by padding them at the start
        let first_start_time = recordings
            .iter()
            .filter_map(|(_, recs)| recs.front().map(|first_rec| first_rec.timestamp))
            .min()
            .ok_or(RecordingError::NoData)?;
        let last_end_time = recordings
            .iter()
            .filter_map(|(_, recs)| {
                recs.back()
                    .map(|last_rec| last_rec.timestamp + samples_to_duration(last_rec.data.len()))
            })
            .max()
            .ok_or(RecordingError::NoData)?;
        dbg!(first_start_time, last_end_time);

        let folder = Path::new(RECORDING_FOLDER)
            .join(self.guild_id.0.to_string())
            .join(
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
                    .to_string(),
            );
        fs::create_dir_all(&folder).await?;

        let mut tasks = Vec::new();
        for (uid, rec) in recordings.into_iter() {
            tasks.push(tokio::spawn(Receiver::save_single_recording(
                cache_and_http.clone(),
                self.guild_id,
                uid,
                rec,
                folder.clone(),
                first_start_time,
                last_end_time,
            )));
        }

        for join_handle in tasks {
            join_handle.await.map_err(std::io::Error::from)??;
        }

        Ok(())
    }

    async fn save_single_recording(
        cache_and_http: CacheHttp,
        guild_id: GuildId,
        user_id: UserId,
        mut rec: VecDeque<VoiceSnippet>,
        folder: PathBuf,
        first_start_time: SystemTime,
        last_end_time: SystemTime,
    ) -> Result<(), RecordingError> {
        // Add a last empty recording at last_end_time to ensure everything ends at same timepoint
        rec.push_back(VoiceSnippet {
            timestamp: last_end_time,
            data: Vec::new(),
        });

        // Assemble all the vectors into one big vector respecting gaps
        let mut data = Vec::new();
        let mut previous_end = first_start_time;

        for mut r in rec.into_iter() {
            // Fill in possible gap. If there is overlap (raises SystemTimeError), we just append and ignore.
            let diff = r
                .timestamp
                .duration_since(previous_end)
                .map(|d| d.as_nanos())
                .unwrap_or(0);
            dbg!(diff, previous_end, r.timestamp, "Filling in gap");

            let missing_samples = nanos_to_samples(diff);
            data.append(&mut vec![0; missing_samples]);

            // Update previous_end before mutating r
            previous_end = r.timestamp + samples_to_duration(r.data.len());
            data.append(&mut r.data);
        }
        dbg!(data.len(), "Samples extracted");

        let UserId(uid) = user_id;
        let name = guild_id
            .member(cache_and_http, uid)
            .await
            .map(|member| member.user.name)
            .unwrap_or_else(|_| uid.to_string());

        let file = folder.join(format!("{}.wav", name));
        let args = [
            "-f",
            "s16le",
            "-ar",
            &SAMPLE_RATE.to_string(),
            "-ac",
            &CHANNEL_COUNT.to_string(),
            "-i",
            "pipe:",
        ];
        let mut child = Command::new("ffmpeg")
            .kill_on_drop(true)
            .args(&args)
            .arg(file.as_os_str())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        {
            let child_stdin = child.stdin.as_mut().unwrap();
            for d in data {
                tokio::io::AsyncWriteExt::write_i16_le(child_stdin, d).await?;
            }
        }

        child.wait_with_output().await?;
        Ok(())
    }
}

#[async_trait]
impl VoiceEventHandler for Receiver {
    #[allow(unused_variables)]
    async fn act(&self, ctx: &EventContext<'_>) -> Option<Event> {
        use EventContext as Ctx;
        match ctx {
            Ctx::SpeakingStateUpdate(Speaking {
                speaking,
                ssrc,
                user_id,
                ..
            }) => {
                // Discord voice calls use RTP, where every sender uses a randomly allocated
                // *Synchronisation Source* (SSRC) to allow receivers to tell which audio
                // stream a received packet belongs to. As this number is not derived from
                // the sender's user_id, only Discord Voice Gateway messages like this one
                // inform us about which random SSRC a user has been allocated. Future voice
                // packets will contain *only* the SSRC.
                //
                // You can implement logic here so that you can differentiate users'
                // SSRCs and map the SSRC to the User ID and maintain this state.
                // Using this map, you can map the `ssrc` in `voice_packet`
                // to the user ID and handle their audio packets separately.

                println!(
                    "Speaking state update: user {:?} has SSRC {:?}, using {:?}",
                    user_id, ssrc, speaking,
                );
                // insert a new user into self.`users`
                let contains_key;
                {
                    contains_key = self.users.read().await.contains_key(ssrc);
                };
                if !contains_key {
                    println!("New user {:?} with ssrc: {:?}", user_id, *ssrc);
                    let mut users = self.users.write().await;
                    users.insert(*ssrc, Arc::new(Mutex::new(UserData::new(user_id.unwrap()))));
                }
            }
            Ctx::SpeakingUpdate(SpeakingUpdateData { ssrc, speaking, .. }) => {
                // You can implement logic here which reacts to a user starting
                // or stopping speaking, and to map their SSRC to User ID.
                println!(
                    "Source {} has {} speaking.",
                    ssrc,
                    if *speaking { "started" } else { "stopped" },
                );
                let user_lock;
                {
                    let users = self.users.read().await;
                    user_lock = users.get(ssrc).cloned()?;
                }

                if *speaking {
                    // Create a new recording if the user starts speaking. We assume that all audio packets we receive between
                    // a user starting and stopping to speak are adjunct.
                    let mut user = user_lock.lock().await;
                    user.recordings.push_back(VoiceSnippet {
                        timestamp: SystemTime::now(),
                        data: Vec::new(),
                    });
                } else {
                    // Start a timeout for the recording. This starts when the user stops speaking.
                    tokio::spawn(async move {
                        sleep(Duration::from_secs(RECORDING_LENGTH)).await;

                        let mut user = user_lock.lock().await;
                        user.recordings
                            .pop_front()
                            .expect("Missing element in Deque");
                        dbg!(user.recordings.len(), "Removed timed out recording");
                    });
                }
            }
            Ctx::VoicePacket(VoiceData { audio, packet, .. }) => {
                // An event which fires for every received audio packet,
                // containing the decoded data.
                if let Some(audio) = audio {
                    // println!(
                    //     "Audio packet's first 5 samples: {:?}",
                    //     audio.get(..5.min(audio.len()))
                    // );
                    // println!(
                    //     "Audio packet sequence {:05} has {:04} bytes (decompressed from {}), SSRC {}",
                    //     packet.sequence.0,
                    //     audio.len() * std::mem::size_of::<i16>(),
                    //     packet.payload.len(),
                    //     packet.ssrc,
                    // );
                    let user_lock;
                    {
                        let users = self.users.read().await;
                        user_lock = users.get(&packet.ssrc).cloned()?;
                    }

                    // Append the audio to the latest recording
                    let mut user = user_lock.lock().await;
                    user.last_voice_activity = SystemTime::now();
                    // insert new audio into user's recordings
                    if let Some(recording) = user.recordings.back_mut() {
                        recording.data.extend(audio);
                    }
                } else {
                    println!("RTP packet, but no audio. Driver may not be configured to decode.");
                }
            }
            Ctx::RtcpPacket(data) => {
                // An event which fires for every received rtcp packet,
                // containing the call statistics and reporting information.
                println!("RTCP packet received: {:?}", data.packet);
            }
            Ctx::ClientDisconnect(ClientDisconnect { user_id, .. }) => {
                // You can implement your own logic here to handle a user who has left the
                // voice channel e.g., finalise processing of statistics etc.
                // You will typically need to map the User ID to their SSRC; observed when
                // first speaking.

                println!("Client disconnected: user {:?}", user_id);
            }
            _ => {
                // We won't be registering this struct for any more event classes.
                unimplemented!()
            }
        }

        None
    }
}

#[derive(Debug)]
pub enum ClientError {
    NotInAChannel,
    UserNotFound,
    DecodingError(songbird::input::error::Error),
    ConnectionError,
    GuildNotFound,
}

#[derive(Clone)]
pub struct Client {
    songbird: Arc<Songbird>,
    pub recorder: Arc<Recorder>,
}

impl Client {
    pub fn new() -> Self {
        let songbird = Songbird::serenity();
        songbird.set_config(SongbirdConfig::default().decode_mode(DecodeMode::Decode));

        Self {
            songbird,
            recorder: Recorder::create(),
        }
    }

    pub fn builder(&self) -> Self {
        Client::new()
    }
    pub async fn join_channel(
        &self,
        guild_id: GuildId,
        channel_id: ChannelId,
    ) -> Result<Arc<Mutex<songbird::Call>>, ClientError> {
        let (call_lock, result) = self.songbird.join(guild_id, channel_id).await;
        result.map_err(|_| ClientError::ConnectionError)?;

        self.recorder
            .register_with_call(guild_id, call_lock.clone())
            .await;

        Ok(call_lock)
    }

    // pub async fn join_user(
    //     &self,
    //     guild_id: GuildId,
    //     user_id: UserId,
    //     cache_and_http: &CacheHttp,
    // ) -> Result<(ChannelId, Arc<Mutex<songbird::Call>>), ClientError> {
    //     let guild = guild_id
    //         .to_guild_cached(cache_and_http)
    //         .ok_or(ClientError::GuildNotFound)?;
    //
    //     let channel_id = guild
    //         .voice_states
    //         .get(&user_id.into())
    //         .and_then(|voice_state| voice_state.channel_id)
    //         .ok_or(ClientError::UserNotFound)?;
    //
    //     dbg!(channel_id, "Joining user in channel");
    //
    //     self.join_channel(guild_id, channel_id)
    //         .await
    //         .map(|call| (channel_id, call))
    // }

    pub async fn leave(&self, guild_id: GuildId) -> Result<(), ClientError> {
        self.songbird
            .remove(guild_id)
            .await
            .map_err(|err| match err {
                JoinError::NoCall => ClientError::NotInAChannel,
                _ => ClientError::ConnectionError,
            })
    }

    pub async fn play(
        &self,
        sound_path: &PathBuf,
        volume_adjustment: f32,
        guild_id: GuildId,
    ) -> Result<(), ClientError> {
        let call_lock = self
            .songbird
            .get(guild_id)
            .ok_or(ClientError::NotInAChannel)?;
        let mut call = call_lock.lock().await;

        let volume_adjustment_string = format!("volume={}dB", volume_adjustment);
        let source = songbird::input::ffmpeg_optioned(
            sound_path,
            &[],
            &[
                "-f",
                "s16le",
                "-ar",
                "48000",
                "-acodec",
                "pcm_f32le",
                "-filter:a",
                &volume_adjustment_string,
                "-",
            ],
        )
        .await
        .map_err(|why| {
            dbg!("Err starting source: {:?}", &why);
            ClientError::DecodingError(why)
        })?;

        call.play_only_source(source);
        Ok(())
    }

    pub async fn stop(&self, guild_id: GuildId) -> Result<(), ClientError> {
        let handler_lock = self
            .songbird
            .get(guild_id)
            .ok_or(ClientError::NotInAChannel)?;

        let mut handler = handler_lock.lock().await;
        handler.stop();

        Ok(())
    }
}

pub trait ClientInit {
    fn register_client(self, client: &Client) -> Self;
}

impl ClientInit for ClientBuilder {
    fn register_client(self, client: &Client) -> Self {
        self.type_map_insert::<ClientKey>(client.clone())
            .register_songbird_with(client.songbird.clone())
    }
}

/// Key used to put the Client into the serenity TypeMap
struct ClientKey;

impl TypeMapKey for ClientKey {
    type Value = Client;
}

/// Retrieve the Client State from a serenity context's
/// shared key-value store.
pub async fn get(ctx: &Context) -> Option<Client> {
    let data = ctx.data.read().await;

    data.get::<ClientKey>().cloned()
}

fn load_token() -> String {
    let file =
        File::open("discord.token").expect("Couldn't find discord.token file in root directory");
    let mut token = String::new();
    let len = BufReader::new(file).read_line(&mut token);
    dbg!(&token);
    token
}

#[group]
#[commands(join, leave, ping, record, transcribe, live)]
struct General;

#[tokio::main]
async fn main() {
    let filter = EnvFilter::from_default_env()
        .add_directive("serenity=off".parse().unwrap())
        .add_directive("songbird=off".parse().unwrap());
    let format = fmtt::format();
    let subscriber = fmtt::fmt()
        .event_format(format)
        .with_env_filter(filter)
        .finish();
    tracing::subscriber::set_global_default(subscriber).expect("setting tracing default failed");
    // Configure the client with your Discord bot token from discord.token file in repo dir.
    let token = load_token();

    let framework = StandardFramework::new()
        .configure(|c| c.prefix("~"))
        .group(&GENERAL_GROUP);

    let intents = GatewayIntents::non_privileged() | GatewayIntents::MESSAGE_CONTENT;

    // Here, we need to configure Songbird to decode all incoming voice packets.
    // If you want, you can do this on a per-call basis---here, we need it to
    // read the audio data that other people are sending us!
    let songbird_config = Config::default().decode_mode(DecodeMode::Decode);
    let client = Client::new();
    let mut connector = SerenityClient::builder(&token, intents)
        .event_handler(Handler)
        .framework(framework)
        .register_songbird_from_config(songbird_config)
        .register_client(&client)
        .await
        .expect("Err creating client");

    let _ = connector
        .start()
        .await
        .map_err(|why| println!("Client ended: {:?}", why));
}

#[command]
#[only_in(guilds)]
async fn join(ctx: &Context, msg: &Message, mut args: Args) -> CommandResult {
    let connect_to = match args.single::<u64>() {
        Ok(id) => ChannelId(id),
        Err(_) => {
            check_msg(
                msg.reply(ctx, "Requires a valid voice channel ID be given")
                    .await,
            );

            return Ok(());
        }
    };

    let guild = msg.guild(&ctx.cache).unwrap();
    let guild_id = guild.id;
    let client = get(ctx)
        .await
        .expect("Songbird Voice client placed in at initialisation.")
        .clone();

    match client.join_channel(guild_id, connect_to).await {
        Ok(_) => {
            msg.channel_id
                .say(
                    &ctx.http,
                    &format!(":white_check_mark: Joined {}", connect_to.mention()),
                )
                .await;
        }
        _ => {
            msg.channel_id
                .say(
                    &ctx.http,
                    &format!(":x: Failed to join {}", connect_to.mention()),
                )
                .await;
        }
    }
    Ok(())
}

async fn live_transcribe(guild_id: GuildId) -> Result<String, RecordingError> {
    // let client = get(ctx)
    //     .await
    //     .expect("Recorder placed in at initialization");
    println!("INSIDE LIVE TRANSCRIBE");
    let name = &(RECORDING_FOLDER.to_owned() + "/" + &guild_id.to_string());
    dbg!(name);

    let rec_iter = std::fs::read_dir(Path::new(name)).expect("NO SUCH RECORDING FOLDER");
    for rec in rec_iter {
        let rec = rec.unwrap().file_name();
        let rec = rec.to_str().expect("ReadDir to File conversion failed");
        let recn = &(name.to_owned() + "/" + rec);
        dbg!(&rec);
        dbg!(&recn);
        for recc in std::fs::read_dir(Path::new(&recn)).expect("NO SUCH VOICE FOLDER") {
            let recc = recc.unwrap().file_name();
            let recc = recc.to_str().expect("ReadDir to File conversion failed");

            dbg!(&recc);
            dbg!(&recc[recc.len() - 3..]);
            // check filetype
            if &recc[recc.len() - 3..] == "wav" {
                // make people know u're doing stuff
                // check_msg(
                //     msg.reply(
                //         ctx,
                //         format!("Started transcribing voice of {}", &recc[0..recc.len() - 4]),
                //     )
                //     .await,
                // );

                let recc = &(recn.to_owned() + "/" + recc);
                let recc = Path::new(&recc);
                dbg!(&recc);
                let transciption = _transcribe(recc, true)
                    .await
                    .unwrap_or("error".to_string())
                    .replace("\n ", "\n");
                match transciption.len() {
                    0 => return Err(RecordingError::NoData), // should work in the error for sure
                    _ => return Ok(transciption),
                }
            }
        }
    }
    Err(RecordingError::NoData)
}
async fn _transcribe(file: &Path, speedup: bool) -> Result<String, RecordingError> {
    use std::thread::available_parallelism;
    let default_parallelism_approx = available_parallelism().unwrap().get();
    dbg!(default_parallelism_approx);
    // sox termog.wav -r 16000 -c 1 -b 16 termog16.wav
    dbg!(file);
    let recsdir = file.parent().unwrap_or(Path::new("."));
    dbg!(recsdir);
    let filename = file.file_name().unwrap_or(OsStr::new("error.err"));
    let filename_no_ext = file.file_stem().unwrap_or(OsStr::new("error"));
    let file = file.to_str().unwrap();

    // create a new dir
    let ready_dir = format!("{}/ready", recsdir.to_str().unwrap_or(""));
    match Path::new(&ready_dir).exists() {
        false => {
            // can't fail
            _ = std::fs::create_dir(&ready_dir);
        }
        true => (),
    }
    let args = [
        file,
        "-r 16000",
        "-c 1",
        "-b 16",
        &format!("{}/{}", &ready_dir, &filename.to_string_lossy()),
    ];
    dbg!(&args);
    let mut child = Command::new("sox")
        .kill_on_drop(true)
        .args(&args)
        // .stdout(Stdio::null())
        // .stderr(Stdio::null())
        .spawn()?;
    let convert_result = child.wait_with_output().await?;
    dbg!(convert_result);
    // ./main -m models/ggml-medium.bin -f ../src/RECS/1102937524176957542/1683751502/rxn16.wav -l auto -otxt name.txt
    // fs::create_dir_all(file.to_owned() + "/out").await?;
    let out_dir = format!("{}/out", recsdir.to_str().unwrap_or(""));
    match Path::new(&out_dir).exists() {
        false => {
            // can't fail
            _ = std::fs::create_dir(&out_dir);
        }
        true => (),
    }
    dbg!(&out_dir);

    let output_txt = format!("{}/{}", &out_dir, &filename_no_ext.to_string_lossy());
    let ready_file = format!("{}/{}", &ready_dir, &filename.to_string_lossy());

    // we have to pass each arg and its value as separate strings for whatever reason... >.<
    // as of now it uses max_threads - 2 to compute the transcription
    let mut args2 = [
        "-t",
        &(default_parallelism_approx - 2).to_string(),
        "-m",
        "stt/models/ggml-medium.bin",
        "-f",
        &ready_file,
        "-l",
        "auto",
        // we can also use -su flag to speed up the process
        // * -su sppeds up the track x2 *
        // "-su",
        "-otxt",
        "-of",
        &output_txt,
    ];
    dbg!(&args2);
    _ = dbg!(env::current_dir());
    let sttpath = "./stt/main";
    let mut child2: Child;
    if speedup {
        child2 = Command::new(sttpath)
            .kill_on_drop(true)
            .args(&args2)
            .arg("-su")
            .spawn()?;
    } else {
        child2 = Command::new(sttpath)
            .kill_on_drop(true)
            .args(&args2)
            .spawn()?;
    }

    let transcription = child2.wait_with_output().await?;

    //remove alreadyh used files, but keep txts
    _ = std::fs::remove_file(ready_file);
    _ = std::fs::remove_file(file);
    dbg!(transcription);
    let contents = read_to_string(output_txt + ".txt")?;
    dbg!(&contents);
    Ok(contents)
}

#[command]
#[only_in(guilds)]
async fn transcribe(ctx: &Context, msg: &Message, mut args: Args) -> CommandResult {
    let client = get(ctx)
        .await
        .expect("Recorder placed in at initialization");
    println!("INSIDE TRANSCRIBE");
    let guild_id = msg.guild_id.unwrap();
    let name = &(RECORDING_FOLDER.to_owned() + "/" + &guild_id.to_string());
    dbg!(name);

    let rec_iter = std::fs::read_dir(Path::new(name)).expect("NO SUCH RECORDING FOLDER");
    for rec in rec_iter {
        let rec = rec.unwrap().file_name();
        let rec = rec.to_str().expect("ReadDir to File conversion failed");
        let recn = &(name.to_owned() + "/" + rec);
        dbg!(&rec);
        dbg!(&recn);
        for recc in std::fs::read_dir(Path::new(&recn)).expect("NO SUCH VOICE FOLDER") {
            let recc = recc.unwrap().file_name();
            let recc = recc.to_str().expect("ReadDir to File conversion failed");

            dbg!(&recc);
            dbg!(&recc[recc.len() - 3..]);
            // check filetype
            if &recc[recc.len() - 3..] == "wav" {
                // make people know u're doing stuff
                check_msg(
                    msg.reply(
                        ctx,
                        format!("Started transcribing voice of {}", &recc[0..recc.len() - 4]),
                    )
                    .await,
                );

                let recc = &(recn.to_owned() + "/" + recc);
                let recc = Path::new(&recc);
                dbg!(&recc);
                let transciption = _transcribe(recc, false)
                    .await
                    .unwrap_or("error".to_string())
                    .replace("\n ", "\n");
                match transciption.len() {
                    0 => (),
                    _ => check_msg(
                        msg.reply_mention(ctx, format!("\n{}", &transciption[1..]))
                            .await,
                    ),
                }
            }
        }
    }

    Ok(())
}

async fn _live(recorder: Arc<Recorder>, cache_http: CacheHttp, guild_id: GuildId) -> String {
    // let client = get(ctx).await.expect("_live command couldn't start client");
    dbg!("[_live inner function started executing]");
    let save_result = recorder.save_recording(guild_id, cache_http).await;
    // let tasks = Vec::new();
    match live_transcribe(guild_id).await {
        Ok(tr) => tr,
        Err(e) => {
            dbg!(e);
            "Couldn't decode".to_string()
        }
    }
}
#[command]
#[only_in(guilds)]
async fn live(ctx: &Context, msg: &Message, mut args: Args) -> CommandResult {
    let client = get(ctx).await.expect("Live command couldn't start client");
    dbg!("[Live command started executing]");
    let guild_id = msg.guild_id.unwrap();
    let channel_id = match args.single::<u64>() {
        Ok(id) => ChannelId(id),
        Err(_) => {
            check_msg(
                msg.reply(ctx, "Requires a valid voice channel ID be given")
                    .await,
            );
            // questionable
            ChannelId(0)
        }
    };
    let channel = ctx.http.get_channel(channel_id.into()).await?;
    let guild_channel = channel.guild().unwrap();
    let users = match guild_channel.members(ctx).await {
        Ok(members) => members,
        Err(_) => {
            dbg!("No users in the channel or error");
            vec![]
        }
    };
    // let mut tasks = Vec::new();
    for user in users {
        if !user.mute {
            // tasks.push(tokio::spawn(_live(
            //     client.recorder.clone(),
            //     ctx.into(),
            //     guild_id,
            // )));
            let t = _live(client.recorder.clone(), ctx.into(), guild_id).await;
            check_msg(
                msg.channel_id
                    .say(&ctx.http, format!(":white_check_mark: {}", t))
                    .await,
            )
        }
    }

    // for join_handle in tasks {
    //     let t = join_handle
    //         .await
    //         .map_err(std::io::Error::from)
    //         .unwrap_or("Couldn't decode".to_string());
    //     msg.channel_id
    //         .say(&ctx.http, format!(":white_check_mark: {}", t))
    //         .await;
    // }
    Ok(())
}
#[command]
#[only_in(guilds)]
async fn record(ctx: &Context, msg: &Message, mut args: Args) -> CommandResult {
    let client = get(ctx)
        .await
        .expect("Recorder placed in at initialization");
    println!("INSIDE RECORDING");
    let connect_to = match args.single::<u64>() {
        Ok(id) => ChannelId(id),
        Err(_) => {
            check_msg(
                msg.reply(ctx, "Requires a valid voice channel ID be given")
                    .await,
            );

            return Ok(());
        }
    };

    let guild_id = msg.guild_id.unwrap();
    // let (handler_lock, conn_result) = client.join(guild_id, connect_to).await;
    // rec.register_with_call(guild_id, handler_lock).await;
    match client.recorder.save_recording(guild_id, ctx.into()).await {
        Ok(_) => check_msg(
            msg.channel_id
                .say(&ctx.http, ":white_check_mark: Recording saved")
                .await,
        ),
        Err(err) => {
            // dbg!(err, "Failed to record");
            match err {
                RecordingError::IoError(_) => check_msg(
                    msg.channel_id
                        .say(&ctx.http, ":x: Failed to save recording")
                        .await,
                ),
                RecordingError::NoData => {
                    check_msg(msg.channel_id.say(&ctx.http, ":x: No data to record").await)
                }
            }
        }
    }
    Ok(())
}
#[command]
#[only_in(guilds)]
async fn leave(ctx: &Context, msg: &Message) -> CommandResult {
    let guild = msg.guild(&ctx.cache).unwrap();
    let guild_id = guild.id;

    let manager = songbird::get(ctx)
        .await
        .expect("Songbird Voice client placed in at initialisation.")
        .clone();
    let has_handler = manager.get(guild_id).is_some();

    if has_handler {
        if let Err(e) = manager.remove(guild_id).await {
            check_msg(
                msg.channel_id
                    .say(&ctx.http, format!("Failed: {:?}", e))
                    .await,
            );
        }

        check_msg(msg.channel_id.say(&ctx.http, "Left voice channel").await);
    } else {
        check_msg(msg.reply(ctx, "Not in a voice channel").await);
    }

    Ok(())
}

#[command]
async fn ping(ctx: &Context, msg: &Message) -> CommandResult {
    check_msg(msg.channel_id.say(&ctx.http, "Pong!").await);

    Ok(())
}

/// Checks that a message successfully sent; if not, then logs why to stdout.
fn check_msg(result: SerenityResult<Message>) {
    if let Err(why) = result {
        println!("Error sending message: {:?}", why);
    }
}
pub struct Recorder {
    guilds: RwLock<HashMap<GuildId, Receiver>>,
}
impl Recorder {
    pub fn create() -> Arc<Self> {
        Arc::new(Self {
            guilds: Default::default(),
        })
    }

    /// Register the recorder as event handler
    pub async fn register_with_call(
        self: &Arc<Self>,
        guild_id: GuildId,
        call_lock: Arc<Mutex<Call>>,
    ) {
        let guild_recorder;
        {
            let mut guilds = self.guilds.write().await;
            guild_recorder = guilds
                .entry(guild_id)
                .or_insert_with(|| Receiver::new(guild_id))
                .clone();
        }

        {
            let mut call = call_lock.lock().await;
            call.add_global_event(
                CoreEvent::SpeakingStateUpdate.into(),
                guild_recorder.clone(),
            );
            call.add_global_event(CoreEvent::SpeakingUpdate.into(), guild_recorder.clone());
            call.add_global_event(CoreEvent::VoicePacket.into(), guild_recorder);
        }
    }

    /// Saves the recording to disk
    pub async fn save_recording(
        &self,
        guild_id: GuildId,
        cache_and_http: CacheHttp,
    ) -> Result<(), RecordingError> {
        let guild_recorder;
        {
            let guilds = self.guilds.read().await;
            guild_recorder = guilds.get(&guild_id).ok_or(RecordingError::NoData)?.clone();
        }

        guild_recorder.save_recording(cache_and_http).await
    }
}

use whisper_rs::{convert_integer_to_float_audio, FullParams, SamplingStrategy, WhisperContext};

struct Whisper {
    ctx: WhisperContext,
}

impl Whisper {
    fn new(path_to_model: &Path) -> Self {
        Self {
            ctx: WhisperContext::new(&path_to_model.to_string_lossy())
                .expect("failed to load a model"),
        }
    }

    async fn convert(&self, audio: Vec<i16>) -> String {
        // let path_to_model = std::env::args().nth(1).unwrap();
        //
        // // load a context and model
        // let ctx = WhisperContext::new(&path_to_model).expect("failed to load model");

        // create a params object
        let params = FullParams::new(SamplingStrategy::Greedy { best_of: 1 });

        // assume we have a buffer of audio data
        // here we'll make a fake one, floating point samples, 32 bit, 16KHz, mono
        // let audio_data = vec![0_f32; 16000 * 2];
        // let audio_data = Vec::new();
        // for i in audio{
        //     audio_da
        // }
        let audio = convert_integer_to_float_audio(&audio);

        // now we can run the model
        let mut state = self.ctx.create_state().expect("failed to create state");
        state.full(params, &audio).expect("failed to run model");

        // fetch the results
        let num_segments = state
            .full_n_segments()
            .expect("failed to get number of segments");
        let mut resulting_text = String::new();
        for i in 0..num_segments {
            let segment = state
                .full_get_segment_text(i)
                .expect("failed to get segment");
            resulting_text.push_str(&segment);
            let start_timestamp = state
                .full_get_segment_t0(i)
                .expect("failed to get segment start timestamp");
            let end_timestamp = state
                .full_get_segment_t1(i)
                .expect("failed to get segment end timestamp");
            println!("[{} - {}]: {}", start_timestamp, end_timestamp, segment);
        }
        resulting_text
    }
}
