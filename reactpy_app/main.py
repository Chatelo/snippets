from reactpy import component, html, run


@component
def App():
    return html.div(html.h1("Reactpy is cool!"),
                    Todo("Learn Reactpy"),
                    Todo("Build something awesome"),
                    Todo("Share with the world"))

@component
def Todo(name):
    return html.p(name)


run(App)