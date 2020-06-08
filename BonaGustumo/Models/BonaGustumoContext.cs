using System;
using System.Collections.Generic;
using System.Data.Entity;
using System.Linq;
using System.Web;

namespace BonaGustumo.Models
{
    public class BonaGustumoContext:DbContext
    {
          public BonaGustumoContext()
            : base("name=BonaGustumoContext")
            {
            }
            public virtual DbSet<LoginViewModel> LoginViewModels { get;set;}
        }
    }
