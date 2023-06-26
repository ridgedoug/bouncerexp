import vakt
from vakt import Guard
from vakt.rules import Eq, Any, StartsWith, And, Greater, Less
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from vakt.storage.sql import SQLStorage, migrations, model
from collections import deque
from datetime import datetime, timedelta

user_to_role = {
    'zixi': 'TechLead',
    'wl': 'Dev',
    'ly': 'SnrDev'
}

compound_roles = {
    'Dev': [],
    'IT': [],
    'SnrDev': ['Dev'],
    'TechLead': ['SnrDev','IT']
}

role_permissions = {
    'Dev': set(['bloq: read', 'bloq: write']),
    'SnrDev': set(['bloq/post:comment|dated_1Y']),
    'TechLead': set(['bloq/post:comment']),
    'IT': set()
}

def dated(upto: str, created_date: str):
    created_datetime = datetime.strptime(created_date, '%d/%m/%Y')
    time_delta = timedelta()
    if upto == '1Y':
        time_delta = timedelta(days=365)
    return datetime.now() - created_datetime < time_delta

func_dict = {
    'dated': dated
}

def get_user_perms(user_id: str) -> set[str]:
    roles = deque([user_to_role[user_id]])
    complete_set = set()
    while roles:
        length = len(roles)
        for i in range(length):
            role = roles.popleft()
            complete_set = complete_set.union(role_permissions[role])
            roles.extend(compound_roles[role])
    return complete_set
    
    

class PowerGuard(Guard):
    @staticmethod
    def check_context_restriction(policy, inquiry):
        """
        Check if context restriction in the policy is satisfied for a given inquiry's context.
        If at least one rule is not present in Inquiry's context -> deny access.
        If at least one rule provided in Inquiry's context is not satisfied -> deny access.
        """
        for key, rule in policy.context.items():
            try:
                ctx_value = inquiry.context[key]
            except KeyError:
                # log.debug("No key '%s' found in Inquiry context", key)
                return False
            if not rule.satisfied(ctx_value, inquiry):
                return False
        
        # checks within inquiry
        if isinstance(inquiry.subject, dict):
            try:
                user_id = inquiry.subject['user_id']
                user_perms = get_user_perms(user_id)
                print(user_perms)
                action = inquiry.action
                resource = inquiry.resource
                perm = f'{resource}:{action}'
                candidate_perm = []
                for p in user_perms:
                    if p.startswith(perm):
                        candidate_perm.append(p)
                print(candidate_perm)
                return_val = len(candidate_perm) > 0
                for i in range(len(candidate_perm)):
                    perm_args = candidate_perm[i].split('|')
                    if len(perm_args) > 1:
                        funcstring, args = perm_args[1].split('_')
                        print(inquiry.context['start_date'])
                        return_val = return_val and func_dict[funcstring](args, inquiry.context['start_date'])
                return return_val
            except:
                print('fail')
        #for key, value in inquiry.context.items():
            
        
        
        
        
        
        return True

comment_policy = vakt.Policy(
    34234,
    actions=[Eq('comment')],
    resources=[StartsWith('bloq/post', ci=True)],
    subjects=[{'user_id': Any()}],
    effect=vakt.ALLOW_ACCESS,
    context={},
    description="""
    Allow to fork or clone any Google repository for
    users that have > 50 and < 999 stars and came from Github
    """
)

# policy = vakt.Policy(
#     123456,
#     actions=[Eq('fork'), Eq('clone')],
#     resources=[StartsWith('repos/Google', ci=True)],
#     subjects=[{'name': Any(), 'stars': And(Greater(50), Less(999))}],
#     effect=vakt.ALLOW_ACCESS,
#     context={'referer': Eq('https://github.com')},
#     description="""
#     Allow to fork or clone any Google repository for
#     users that have > 50 and < 999 stars and came from Github
#     """
# )



engine = create_engine('postgresql://postgres:6167@localhost/ridgedoug')
storage = SQLStorage(scoped_session=scoped_session(sessionmaker(bind=engine)))
migrationset = migrations.SQLMigrationSet(storage)
migrationset.up()
# storage.add(comment_policy)
guard = PowerGuard(storage, vakt.RulesChecker())

inq = vakt.Inquiry(action='fork',
                   resource='repos/google/tensorflow',
                   subject={'name': 'larry', 'stars': 80},
                   context={'referer': 'https://github.com'})

# assert guard.is_allowed(inq)
comment_inq = vakt.Inquiry(action='comment',
                           resource='bloq/post',
                           subject={'user_id': 'zixi'},
                           context={'start_date': '12/01/2022'})
assert guard.is_allowed(comment_inq)

# print(get_user_perms('ly'))