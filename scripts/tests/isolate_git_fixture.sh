# Source before running Git in an owned test repository.
git_fixture_local_env=$(git rev-parse --local-env-vars)
for git_fixture_variable in $git_fixture_local_env; do
  unset "$git_fixture_variable"
done
unset git_fixture_local_env git_fixture_variable
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 GIT_TEMPLATE_DIR=
