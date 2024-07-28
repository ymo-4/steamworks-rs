use std::cell::{Cell, RefCell};
use std::net::Ipv4Addr;
use std::ptr;
use std::rc::Rc;
use std::time::Duration;

use super::*;

macro_rules! matchmaking_servers_callback {
    (
        $name:ident;
        $self:ident;
        ($($additional_name:ident : $additional_type:ty where $additional_content:block),*);
        $(
            $fn_name:ident($clear_after_call:tt): ( $( $fn_arg_name:ident: $cpp_fn_arg:ty => $rust_fn_arg:ty where $normalize:tt ),* )
        ),*
    ) => {
        paste::item! {
            $(
                extern fn [<$name:lower _ $fn_name _virtual>]($self: *mut [<$name CallbacksReal>] $(, $fn_arg_name: $cpp_fn_arg)*) {
                    unsafe {
                        $(
                            #[allow(unused_parens)]
                            let [<$fn_arg_name _norm>]: $rust_fn_arg = $normalize;
                        )*
                        // In case of dropping rust_callbacks inside $fn_name
                        let rc_fn = Rc::clone(&(*(*$self).rust_callbacks).$fn_name);
                        (*rc_fn)($([<$fn_arg_name _norm>]),*);
                        $clear_after_call;
                    }
                }
            )*

            pub struct [<$name Callbacks>] {
                $(
                    pub (self) $fn_name: Rc<Box<dyn Fn($($rust_fn_arg),*)>>,
                )*
                $(
                    pub (self) $additional_name: $additional_type,
                )*
            }

            impl [<$name Callbacks>] {
                pub fn new($($fn_name: Box<dyn Fn($($rust_fn_arg),*)>),*) -> Self {
                    Self {
                        $($fn_name: Rc::new($fn_name),)*
                        $($additional_name: $additional_content,)*
                    }
                }
            }

            #[repr(C)]
            struct [<$name CallbacksReal>] {
                pub vtable: *mut [<$name CallbacksVirtual>],
                pub rust_callbacks: *mut [<$name Callbacks>],
            }

            #[repr(C)]
            struct [<$name CallbacksVirtual>] {
                $(
                    pub $fn_name: extern fn(*mut [<$name CallbacksReal>] $(, $cpp_fn_arg)*)
                ),*
            }

            unsafe fn [<create_ $name:lower>](rust_callbacks: [<$name Callbacks>]) -> *mut [<$name CallbacksReal>] {
                let rust_callbacks = Box::into_raw(Box::new(rust_callbacks));
                let vtable = Box::into_raw(Box::new([<$name CallbacksVirtual>] {
                    $(
                        $fn_name: [<$name:lower _ $fn_name _virtual>]
                    ),*
                }));
                let real = Box::into_raw(Box::new([<$name CallbacksReal>] {
                    vtable,
                    rust_callbacks,
                }));

                real
            }

            unsafe fn [<free_ $name:lower>](real: *mut [<$name CallbacksReal>]) {
                drop(Box::from_raw((*real).rust_callbacks));
                drop(Box::from_raw((*real).vtable));
                drop(Box::from_raw(real));
            }
        }
    };
}

macro_rules! gen_server_list_fn {
    (
        $name:ident, $sys_method:ident
    ) => {
        /// # Usage
        ///
        /// Request must be released at the end of using. For more details see [`ServerListRequest::release`]
        ///
        /// # Arguments
        ///
        /// * app_id: The app to request the server list of.
        /// * filters: An array of filters to only retrieve servers the user cares about.
        /// A list of the keys & values can be found
        /// [here](https://partner.steamgames.com/doc/api/ISteamMatchmakingServers#MatchMakingKeyValuePair_t).
        ///
        /// # Errors
        ///
        /// Every filter's key and value must take 255 bytes or under, otherwise `Err` is returned.
        pub fn $name<ID: Into<AppId>>(
            &self,
            app_id: ID,
            filters: &HashMap<&str, &str>,
            callbacks: ServerListCallbacks,
        ) -> Result<(), ()> {
            let app_id = app_id.into().0;
            let mut filters = {
                let mut vec = Vec::with_capacity(filters.len());
                for i in filters {
                    let key_bytes = i.0.as_bytes();
                    let value_bytes = i.1.as_bytes();

                    // Max length is 255, so 256th byte will always be nul-terminator
                    if key_bytes.len() >= 256 || value_bytes.len() >= 256 {
                        return Err(());
                    }

                    let mut key = [0i8; 256];
                    let mut value = [0i8; 256];

                    unsafe {
                        key.as_mut_ptr()
                            .copy_from(key_bytes.as_ptr().cast(), key_bytes.len());
                        value
                            .as_mut_ptr()
                            .copy_from(value_bytes.as_ptr().cast(), value_bytes.len());
                    }

                    vec.push(sys::MatchMakingKeyValuePair_t {
                        m_szKey: key,
                        m_szValue: value,
                    });
                }
                vec.shrink_to_fit();

                vec
            };

            unsafe {
                let callbacks = create_serverlist(callbacks);

                let request = ServerListRequest::get_unchecked(callbacks);
                request.mms.set(self.mms);
                request.real.set(callbacks);

                let handle = sys::$sys_method(
                    self.mms,
                    app_id,
                    &mut filters.as_mut_ptr() as *mut *mut _,
                    filters.len().try_into().unwrap(),
                    callbacks.cast(),
                );
                request.h_req.set(handle);
            }

            Ok(())
        }
    };
}

pub struct GameServerItem {
    pub appid: u32,
    pub players: i32,
    pub do_not_refresh: bool,
    pub successful_response: bool,
    pub have_password: bool,
    pub secure: bool,
    pub bot_players: i32,
    pub ping: Duration,
    pub max_players: i32,
    pub server_version: i32,
    pub steamid: u64,
    pub last_time_played: Duration,
    pub addr: Ipv4Addr,
    pub query_port: u16,
    pub connection_port: u16,
    pub game_description: String,
    pub server_name: String,
    pub game_dir: String,
    pub map: String,
    pub tags: String,
}

impl GameServerItem {
    unsafe fn from_ptr(raw: *const sys::gameserveritem_t) -> Self {
        let raw = *raw;
        Self {
            appid: raw.m_nAppID,
            players: raw.m_nPlayers,
            bot_players: raw.m_nBotPlayers,
            ping: Duration::from_millis(raw.m_nPing.try_into().unwrap()),
            max_players: raw.m_nMaxPlayers,
            server_version: raw.m_nServerVersion,
            steamid: raw.m_steamID.m_steamid.m_unAll64Bits,

            do_not_refresh: raw.m_bDoNotRefresh,
            successful_response: raw.m_bHadSuccessfulResponse,
            have_password: raw.m_bPassword,
            secure: raw.m_bSecure,

            addr: Ipv4Addr::from(raw.m_NetAdr.m_unIP),
            query_port: raw.m_NetAdr.m_usQueryPort,
            connection_port: raw.m_NetAdr.m_usConnectionPort,

            game_description: CStr::from_ptr(raw.m_szGameDescription.as_ptr())
                .to_string_lossy()
                .into_owned(),
            server_name: CStr::from_ptr(raw.m_szServerName.as_ptr())
                .to_string_lossy()
                .into_owned(),
            game_dir: CStr::from_ptr(raw.m_szGameDir.as_ptr())
                .to_string_lossy()
                .into_owned(),
            map: CStr::from_ptr(raw.m_szMap.as_ptr())
                .to_string_lossy()
                .into_owned(),
            tags: CStr::from_ptr(raw.m_szGameTags.as_ptr())
                .to_string_lossy()
                .into_owned(),

            last_time_played: Duration::from_secs(raw.m_ulTimeLastPlayed.into()),
        }
    }
}

matchmaking_servers_callback!(
    Ping;
    _self;
    ();
    responded({}): (info: *const sys::gameserveritem_t => GameServerItem where { GameServerItem::from_ptr(info) }),
    failed({ free_ping(_self) }): ()
);

matchmaking_servers_callback!(
    PlayerDetails;
    _self;
    ();
    add_player({}): (
        name: *const std::os::raw::c_char => &CStr where { CStr::from_ptr(name) },
        score: i32 => i32 where {score},
        time_played: f32 => f32 where {time_played}
    ),
    failed({ free_playerdetails(_self) }): (),
    refresh_complete({ free_playerdetails(_self) }): ()
);

matchmaking_servers_callback!(
    ServerRules;
    _self;
    ();
    add_rule({}): (
        rule: *const std::os::raw::c_char => &CStr where { CStr::from_ptr(rule) },
        value: *const std::os::raw::c_char => &CStr where { CStr::from_ptr(value) }
    ),
    failed({ free_serverrules(_self) }): (),
    refresh_complete({ free_serverrules(_self) }): ()
);

matchmaking_servers_callback!(
    ServerList;
    _self;
    (
        req: Rc<ServerListRequest> where {
            Rc::new(ServerListRequest {
                h_req: Cell::new(ptr::null_mut()),
                released: Cell::new(false),
                mms: Cell::new(ptr::null_mut()),
                real: Cell::new(ptr::null_mut()),
                called_in: Cell::new(CalledIn::None),
            })
        }
    );
    responded({}): (
        request: sys::HServerListRequest => &ServerListRequest where { &*ServerListRequest::get(_self, request, CalledIn::Responded) },
        server: i32 => i32 where {server}
    ),
    failed({}): (
        request: sys::HServerListRequest => &ServerListRequest where { &*ServerListRequest::get(_self, request, CalledIn::Failed) },
        server: i32 => i32 where {server}
    ),
    refresh_complete({ history_prefree(_self) }): (
        request: sys::HServerListRequest => &ServerListRequest where { &*ServerListRequest::get(_self, request, CalledIn::RefreshComplete) },
        response: ServerResponse => ServerResponse where {response}
    )
);

unsafe fn history_prefree(_self: *mut ServerListCallbacksReal) {
    let rc = ServerListRequest::get_unchecked(_self);
    if !rc
        .is_refreshing()
        .expect("This shouldn't panic. But if it's - make an issue")
    {
        rc.release_unchecked();
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
pub enum ServerResponse {
    ServerResponded = 0,
    ServerFailedToRespond = 1,
    NoServersListedOnMasterServer = 2,
}

#[derive(Debug, Copy, Clone, Hash, PartialEq, Eq)]
enum CalledIn {
    Responded,
    Failed,
    RefreshComplete,

    None,
}

impl CalledIn {
    /// ```no_rust
    /// Responded, Failed -> true
    /// RefreshComplete -> false
    /// None -> panic!
    /// ```
    fn is_default(&self) -> bool {
        let val = *self;
        if val == Self::Responded || val == Self::Failed {
            true
        } else if val == Self::RefreshComplete {
            false
        } else {
            panic!("Should never be called on None. Go to github and make an issue!")
        }
    }
}

pub struct ServerListRequest {
    pub(self) released: Cell<bool>,
    pub(self) h_req: Cell<sys::HServerListRequest>,
    pub(self) mms: Cell<*mut sys::ISteamMatchmakingServers>,
    pub(self) real: Cell<*mut ServerListCallbacksReal>,
    pub(self) called_in: Cell<CalledIn>,
}

impl ServerListRequest {
    pub(self) unsafe fn get_unchecked(_self: *mut ServerListCallbacksReal) -> Rc<Self> {
        let rust_callbacks = &*(*_self).rust_callbacks;
        Rc::clone(&rust_callbacks.req)
    }

    pub(self) unsafe fn get(
        _self: *mut ServerListCallbacksReal,
        request: sys::HServerListRequest,
        called_in: CalledIn,
    ) -> Rc<Self> {
        let rc = Self::get_unchecked(_self);
        rc.called_in.set(called_in);

        // In case callback is called faster then function set h_req.
        // Just in case, chance of that is very low.
        if rc.h_req.get().is_null() {
            rc.h_req.set(request);
        }

        rc
    }

    /// # Usage
    ///
    /// Cancels any pending query on it if there's a pending
    /// query in progress. Releasing all heap allocated
    /// structures used for callbacks. The `refresh_complete`
    /// callback will not be posted when request is released.
    ///
    /// Further using methods on this request after `release`
    /// called will always result in `None`
    pub fn release(&self) {
        unsafe {
            if self.released.get() || !self.called_in.get().is_default() {
                return;
            }

            self.release_unchecked();
        }
    }

    pub(self) unsafe fn release_unchecked(&self) {
        self.released.set(true);
        sys::SteamAPI_ISteamMatchmakingServers_ReleaseRequest(self.mms.get(), self.h_req.get());

        free_serverlist(self.real.get());
    }

    fn released(&self) -> Option<()> {
        if self.released.get() {
            None
        } else {
            Some(())
        }
    }

    /// # Errors
    ///
    /// None if called on the released request
    pub fn get_server_count(&self) -> Option<i32> {
        unsafe {
            self.released()?;

            Some(sys::SteamAPI_ISteamMatchmakingServers_GetServerCount(
                self.mms.get(),
                self.h_req.get(),
            ))
        }
    }

    /// # Errors
    ///
    /// None if called on the released request
    pub fn get_server_details(&self, server: i32) -> Option<GameServerItem> {
        unsafe {
            self.released()?;

            // Should we then free this pointer?
            let server_item = sys::SteamAPI_ISteamMatchmakingServers_GetServerDetails(
                self.mms.get(),
                self.h_req.get(),
                server,
            );

            Some(GameServerItem::from_ptr(server_item))
        }
    }

    /// # Errors
    ///
    /// None if called on the released request
    pub fn refresh_query(&self) -> Option<()> {
        unsafe {
            self.released()?;

            sys::SteamAPI_ISteamMatchmakingServers_RefreshQuery(self.mms.get(), self.h_req.get());

            Some(())
        }
    }

    /// # Errors
    ///
    /// None if called on the released request
    pub fn is_refreshing(&self) -> Option<bool> {
        unsafe {
            self.released()?;

            Some(sys::SteamAPI_ISteamMatchmakingServers_IsRefreshing(
                self.mms.get(),
                self.h_req.get(),
            ))
        }
    }
}

/// Access to the steam MatchmakingServers interface
pub struct MatchmakingServers<Manager> {
    pub(crate) mms: *mut sys::ISteamMatchmakingServers,
    pub(crate) _inner: Arc<Inner<Manager>>,
}

impl<Manager> MatchmakingServers<Manager> {
    pub fn ping_server(&self, ip: std::net::Ipv4Addr, port: u16, callbacks: PingCallbacks) {
        unsafe {
            let callbacks = create_ping(callbacks);

            sys::SteamAPI_ISteamMatchmakingServers_PingServer(
                self.mms,
                ip.into(),
                port,
                callbacks.cast(),
            );
        }
    }

    pub fn player_details(
        &self,
        ip: std::net::Ipv4Addr,
        port: u16,
        callbacks: PlayerDetailsCallbacks,
    ) {
        unsafe {
            let callbacks = create_playerdetails(callbacks);

            sys::SteamAPI_ISteamMatchmakingServers_PlayerDetails(
                self.mms,
                ip.into(),
                port,
                callbacks.cast(),
            );
        }
    }

    pub fn server_rules(&self, ip: std::net::Ipv4Addr, port: u16, callbacks: ServerRulesCallbacks) {
        unsafe {
            let callbacks = create_serverrules(callbacks);

            sys::SteamAPI_ISteamMatchmakingServers_ServerRules(
                self.mms,
                ip.into(),
                port,
                callbacks.cast(),
            );
        }
    }

    /// # Usage
    ///
    /// Request must be released at the end of using. For more details see [`ServerListRequest::release`]
    ///
    /// # Arguments
    ///
    /// * app_id: The app to request the server list of.
    pub fn lan_server_list<ID: Into<AppId>>(&self, app_id: ID, callbacks: ServerListCallbacks) {
        unsafe {
            let app_id = app_id.into().0;

            let callbacks = create_serverlist(callbacks);

            let request = ServerListRequest::get_unchecked(callbacks);
            request.mms.set(self.mms);
            request.real.set(callbacks);

            let handle = sys::SteamAPI_ISteamMatchmakingServers_RequestLANServerList(
                self.mms,
                app_id,
                callbacks.cast(),
            );
            request.h_req.set(handle);
        }
    }

    gen_server_list_fn!(
        internet_server_list,
        SteamAPI_ISteamMatchmakingServers_RequestInternetServerList
    );
    gen_server_list_fn!(
        favorites_server_list,
        SteamAPI_ISteamMatchmakingServers_RequestFavoritesServerList
    );
    gen_server_list_fn!(
        history_server_list,
        SteamAPI_ISteamMatchmakingServers_RequestHistoryServerList
    );
    gen_server_list_fn!(
        friends_server_list,
        SteamAPI_ISteamMatchmakingServers_RequestFriendsServerList
    );
}

#[test]
fn test_internet_servers() {
    let (client, single) = Client::init_app(304930).unwrap();

    let data = std::rc::Rc::new(Mutex::new(0));
    let data2 = std::rc::Rc::clone(&data);
    let data3 = std::rc::Rc::clone(&data);
    let callbacks = ServerListCallbacks::new(
        Box::new(move |list, server| {
            let details = list.get_server_details(server).unwrap();
            println!("{} : {}", details.server_name, details.map);
            *data.lock().unwrap() += 1;
        }),
        Box::new(move |_list, _server| {
            println!("failed");
            *data2.lock().unwrap() += 1;
        }),
        Box::new(move |list, _response| {
            println!("{}", data3.lock().unwrap());
        }),
    );

    let mut map = HashMap::new();
    map.insert("map", "PEI");
    let _ = client
        .matchmaking_servers()
        .internet_server_list(304930, &map, callbacks)
        .unwrap();

    for _ in 0..3000 {
        single.run_callbacks();
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}
