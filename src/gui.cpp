#include "gui.h"

#include "gui_view.h"
#include "json_util.h"

// The generated header and Slint's own are not held to this project's /W4 /WX: included
// with angle brackets, they are external headers (/external:anglebrackets /external:W0).
#ifdef _MSC_VER
#pragma warning(push, 0)
#endif
#include <main_window.h>
#ifdef _MSC_VER
#pragma warning(pop)
#endif

#include <chrono>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace pf {

namespace {

// Slint aborts the process when something is posted to an event loop that has ended (it
// unwraps the error), so every post goes through PostToUi, and nothing is posted once
// RunGui's loop has returned.
std::mutex g_loopMu;
bool g_loopAlive = false;
bool g_quitRequested = false;

bool PostToUi(std::function<void()> f) {
    std::lock_guard<std::mutex> lock(g_loopMu);
    if (!g_loopAlive) return false;
    slint::invoke_from_event_loop(std::move(f));
    return true;
}

// The one thread that calls the API: a save waits on the engine (up to its stop budget), and
// the window must not.
class Worker {
public:
    Worker() : thread_([this] { Loop(); }) {}
    ~Worker() { Stop(); }
    Worker(const Worker&) = delete;
    Worker& operator=(const Worker&) = delete;

    void Post(std::function<void()> job) {
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (stop_) return;
            jobs_.push_back(std::move(job));
        }
        cv_.notify_one();
    }

    // Drops what has not started and waits for the job that has.
    void Stop() {
        {
            std::lock_guard<std::mutex> lock(mu_);
            stop_ = true;
            jobs_.clear();
        }
        cv_.notify_one();
        if (thread_.joinable()) thread_.join();
    }

private:
    void Loop() {
        for (;;) {
            std::function<void()> job;
            {
                std::unique_lock<std::mutex> lock(mu_);
                cv_.wait(lock, [this] { return stop_ || !jobs_.empty(); });
                if (stop_) return;
                job = std::move(jobs_.front());
                jobs_.pop_front();
            }
            try {
                job();
            } catch (...) {
            }
        }
    }

    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<std::function<void()>> jobs_;
    bool stop_ = false;
    std::thread thread_;  // last: started once the members above exist
};

slint::SharedString S(const std::string& s) { return slint::SharedString(std::string_view(s)); }
std::string U(const slint::SharedString& s) { return std::string(std::string_view(s)); }

// The model holds `next` afterwards; rows that did not change are left alone, so that the
// list keeps its scroll position and its buttons their hover state across polls.
template <typename T>
void SyncModel(const std::shared_ptr<slint::VectorModel<T>>& model, const std::vector<T>& next) {
    const size_t have = model->row_count();
    for (size_t i = 0; i < next.size() && i < have; ++i) {
        if (!(*model->row_data(i) == next[i])) model->set_row_data(i, next[i]);
    }
    for (size_t i = have; i < next.size(); ++i) model->push_back(next[i]);
    for (size_t i = have; i > next.size(); --i) model->erase(i - 1);
}

// Lives on RunGui's stack; touched only on the UI thread (the worker reaches it through
// PostToUi, which runs there).
class Window {
public:
    explicit Window(const GuiOptions& opts)
        : opts_(opts),
          lang_(GuiLangFromTag(opts.langTag)),
          win_(MainWindow::create()),
          rows_(std::make_shared<slint::VectorModel<RuleRow>>()),
          banners_(std::make_shared<slint::VectorModel<Banner>>()),
          listenLabels_(std::make_shared<slint::VectorModel<slint::SharedString>>()),
          egressLabels_(std::make_shared<slint::VectorModel<slint::SharedString>>()) {
        win_->global<Tr>().set_zh(lang_ == GuiLang::Zh);
        win_->set_version(S(opts_.version));
        win_->set_data_dir(S(opts_.dataDir));
        win_->set_rules(rows_);
        win_->set_banners(banners_);
        win_->set_listen_labels(listenLabels_);
        win_->set_egress_labels(egressLabels_);

        win_->on_add_rule([this] { OpenEditor(nullptr); });
        win_->on_edit_rule([this](slint::SharedString id) {
            const json* r = FindRule(U(id));
            if (r) OpenEditor(r);
        });
        win_->on_toggle_rule([this](slint::SharedString id) {
            const json* r = FindRule(U(id));
            if (!r) return;
            const auto en = r->find("enabled");
            const bool enabled = en != r->end() && en->is_boolean() && en->get<bool>();
            Write("api/rules/" + U(id) + (enabled ? "/disable" : "/enable"));
        });
        win_->on_delete_rule([this](slint::SharedString id) { Write("api/rules/" + U(id) + "/delete"); });
        win_->on_save_rule([this] { Save(); });
        win_->on_exit_app([] { slint::quit_event_loop(); });
    }

    void Run() {
        poll_.start(slint::TimerMode::Repeated, std::chrono::milliseconds(1000), [this] { Poll(); });
        Poll();
        win_->show();
        slint::run_event_loop();
        poll_.stop();
        toastTimer_.stop();
        win_->hide();
    }

    // After the loop: no more posts can arrive, so the worker may be joined here.
    void StopWorker() { worker_.Stop(); }

private:
    std::string T(const char* zh, const char* en) const { return lang_ == GuiLang::Zh ? zh : en; }

    std::string ErrorText(const GuiReply& r) const {
        std::string code;
        JsonGetString(ParseJsonNoThrow(r.body), "error", &code);
        if (!code.empty()) return GuiCodeText(code, lang_);
        return T("错误：", "Error: ") + std::to_string(r.status);
    }

    void Toast(const std::string& text, bool error) {
        win_->set_toast_error(error);
        win_->set_toast_text(S(text));
        // A new toast restarts the clock of the one it replaces.
        toastTimer_.start(slint::TimerMode::SingleShot, std::chrono::milliseconds(error ? 6000 : 2500),
                          [this] { win_->set_toast_text(slint::SharedString()); });
    }

    // ---- Reading -----------------------------------------------------------------------------
    void Poll() {
        if (pollInFlight_) return;
        pollInFlight_ = true;
        const GuiCall call = opts_.call;
        worker_.Post([this, call] {
            GuiReply r = call("GET", "api/state", "");
            PostToUi([this, r] { OnState(r); });
        });
    }

    void OnState(const GuiReply& r) {
        pollInFlight_ = false;
        std::string code;
        const json body = ParseJsonNoThrow(r.body);
        JsonGetString(body, "error", &code);
        if (r.status == 503 && code == "starting") {
            win_->set_loading(true);
            return;
        }
        if (r.status != 200 || !body.is_object()) {
            win_->set_loading(false);
            SyncModel(banners_, {Banner{S(T("插件没有响应。", "The plugin is not responding.")), true}});
            return;
        }
        state_ = body;
        const GuiView v = BuildGuiView(state_, lang_);
        std::vector<Banner> banners;
        for (const GuiBanner& b : v.banners) banners.push_back(Banner{S(b.text), b.error});
        std::vector<RuleRow> rows;
        for (const GuiRuleRow& x : v.rows) {
            RuleRow row;
            row.id = S(x.id);
            row.enabled = x.enabled;
            row.name = S(x.name);
            row.proto = S(x.proto);
            row.route = S(x.route);
            row.egress = S(x.egress);
            row.status = S(x.status);
            row.status_detail = S(x.statusDetail);
            row.status_kind = x.statusKind;
            row.conns = S(x.conns);
            row.conns_sub = S(x.connsSub);
            row.up = S(x.up);
            row.down = S(x.down);
            row.last_error = S(x.lastError);
            row.last_error_at = S(x.lastErrorAt);
            rows.push_back(std::move(row));
        }
        SyncModel(banners_, banners);
        SyncModel(rows_, rows);
        win_->set_loading(false);
        // A confirmation for a rule that is gone (deleted elsewhere) does not linger.
        const std::string pending = U(win_->get_pending_delete());
        if (!pending.empty() && !FindRule(pending)) win_->set_pending_delete(slint::SharedString());
    }

    const json* FindRule(const std::string& id) const {
        auto it = state_.is_object() ? state_.find("rules") : state_.end();
        if (!state_.is_object() || it == state_.end() || !it->is_array()) return nullptr;
        for (const json& r : *it) {
            std::string rid;
            if (JsonGetString(r, "id", &rid) && rid == id) return &r;
        }
        return nullptr;
    }

    // ---- Writing -----------------------------------------------------------------------------
    // A write, then a fresh state; `done` gets the write's reply on the UI thread.
    void Post(const std::string& path, const std::string& body, std::function<void(const GuiReply&)> done) {
        win_->set_busy(true);
        const GuiCall call = opts_.call;
        worker_.Post([this, call, path, body, done] {
            GuiReply w = call("POST", path, body.empty() ? std::string("{}") : body);
            GuiReply s = call("GET", "api/state", "");
            PostToUi([this, w, s, done] {
                win_->set_busy(false);
                done(w);
                pollInFlight_ = true;  // OnState clears it
                OnState(s);
            });
        });
    }

    void Write(const std::string& path) {
        Post(path, "", [this](const GuiReply& r) {
            if (r.status == 200) {
                Toast(T("已保存", "Saved"), false);
            } else {
                Toast(ErrorText(r), true);
            }
        });
    }

    void OpenEditor(const json* rule) {
        std::string id;
        if (rule) JsonGetString(*rule, "id", &id);
        editingId_ = id;
        const GuiForm f = GuiFormFromRule(rule);

        static const json kNoAddrs = json::array();
        auto la = state_.is_object() ? state_.find("localAddrs") : state_.end();
        const json& addrs = state_.is_object() && la != state_.end() ? *la : kNoAddrs;
        listen_ = GuiListenChoices(addrs, f.listenAddr, lang_);
        json egress = json::object();
        if (rule && rule->is_object()) {
            auto e = rule->find("egress");
            if (e != rule->end()) egress = *e;
        }
        egress_ = GuiEgressChoices(egress, lang_);

        std::vector<slint::SharedString> labels;
        int listenIndex = 0;
        for (size_t i = 0; i < listen_.size(); ++i) {
            labels.push_back(S(listen_[i].label));
            if (listen_[i].value == f.listenAddr) listenIndex = static_cast<int>(i);
        }
        SyncModel(listenLabels_, labels);
        labels.clear();
        int egressIndex = 0;
        for (size_t i = 0; i < egress_.size(); ++i) {
            labels.push_back(S(egress_[i].label));
            if (egress_[i].value == f.egress) egressIndex = static_cast<int>(i);
        }
        SyncModel(egressLabels_, labels);

        win_->set_editing_new(rule == nullptr);
        win_->set_f_name(S(f.name));
        win_->set_f_proto(f.udp ? 1 : 0);
        win_->set_f_listen(listenIndex);
        win_->set_f_listen_port(S(f.listenPort));
        win_->set_f_remote_host(S(f.remoteHost));
        win_->set_f_remote_port(S(f.remotePort));
        win_->set_f_egress(egressIndex);
        win_->set_f_max_conn(S(f.maxConnections));
        win_->set_f_udp_idle(S(f.udpIdleSec));
        win_->set_f_enabled(f.enabled);
        win_->set_f_lan_ack(f.lanAck);
        win_->set_form_error(slint::SharedString());
        win_->set_editor_open(true);
    }

    void Save() {
        GuiForm f;
        f.name = U(win_->get_f_name());
        f.udp = win_->get_f_proto() == 1;
        const int li = win_->get_f_listen();
        f.listenAddr = li >= 0 && static_cast<size_t>(li) < listen_.size() ? listen_[static_cast<size_t>(li)].value
                                                                            : std::string("127.0.0.1");
        f.listenPort = U(win_->get_f_listen_port());
        f.remoteHost = U(win_->get_f_remote_host());
        f.remotePort = U(win_->get_f_remote_port());
        const int ei = win_->get_f_egress();
        f.egress = ei >= 0 && static_cast<size_t>(ei) < egress_.size() ? egress_[static_cast<size_t>(ei)].value
                                                                         : std::string("direct");
        f.maxConnections = U(win_->get_f_max_conn());
        f.udpIdleSec = U(win_->get_f_udp_idle());
        f.enabled = win_->get_f_enabled();
        f.lanAck = win_->get_f_lan_ack();
        if (f.listenAddr != "127.0.0.1" && !f.lanAck) {
            win_->set_form_error(S(GuiCodeText("lan_ack_required", lang_)));
            return;
        }
        const std::string path = editingId_.empty() ? std::string("api/rules") : "api/rules/" + editingId_;
        Post(path, DumpSafe(GuiFormToRule(f)), [this](const GuiReply& r) {
            if (r.status == 200) {
                win_->set_editor_open(false);
                win_->set_form_error(slint::SharedString());
                Toast(T("已保存", "Saved"), false);
            } else {
                win_->set_form_error(S(ErrorText(r)));
            }
        });
    }

    GuiOptions opts_;
    GuiLang lang_;
    slint::ComponentHandle<MainWindow> win_;
    std::shared_ptr<slint::VectorModel<RuleRow>> rows_;
    std::shared_ptr<slint::VectorModel<Banner>> banners_;
    std::shared_ptr<slint::VectorModel<slint::SharedString>> listenLabels_;
    std::shared_ptr<slint::VectorModel<slint::SharedString>> egressLabels_;
    slint::Timer poll_;
    slint::Timer toastTimer_;
    bool pollInFlight_ = false;
    json state_;  // the last api/state answer
    std::string editingId_;  // "" = a new rule
    std::vector<GuiChoice> listen_;
    std::vector<GuiChoice> egress_;
    Worker worker_;  // last: destroyed (joined) first
};

}  // namespace

void RunGui(const GuiOptions& opts) {
    Window w(opts);
    {
        std::lock_guard<std::mutex> lock(g_loopMu);
        if (g_quitRequested) return;
        // From here a GuiQuit posts its quit; posted before the loop runs, it waits in the
        // queue and ends the loop as soon as it starts.
        g_loopAlive = true;
    }
    w.Run();
    {
        std::lock_guard<std::mutex> lock(g_loopMu);
        g_loopAlive = false;
    }
    w.StopWorker();
}

void GuiQuit() {
    std::lock_guard<std::mutex> lock(g_loopMu);
    g_quitRequested = true;
    if (g_loopAlive) slint::invoke_from_event_loop([] { slint::quit_event_loop(); });
}

}  // namespace pf
